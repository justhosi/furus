//! exFAT directory entries: the 0x85/0xC0/0xC1 entry set a file or
//! directory is made of (S10 part B1).
//!
//! Every byte layout below was read from the Microsoft exFAT
//! specification and measured against what actually ends up on a
//! volume: an image was formatted with `mkfs.exfat` 1.4.3, mounted
//! through the Linux exFAT driver, a tree was created, and the raw
//! clusters dumped afterwards (the byte pins in this file's tests cite
//! that run). The two agree:
//!
//! * the **file entry** (0x85) carries the set checksum at bytes 2..=3,
//!   FileAttributes at 4, and the three timestamp triples — the 32-bit
//!   DOS `(date << 16) | time` stamps at 8/12/16, the 10 ms increments
//!   (u8, 0..=199) at 20/21, and the UTC offsets (u8) at 22/23/24;
//! * the **stream extension** (0xC0) carries NameLength as one byte at
//!   offset 3 and NameHash at 4, ValidDataLength at 8, then — per the
//!   generic secondary template, exactly like the measured `mkfs`
//!   writes — FirstCluster at 20 and DataLength at 24;
//! * the **file name** entries (0xC1) store up to 15 UTF-16LE units at
//!   offset 2 (30 bytes), byte 1 zero, the name case-preserved with
//!   interior spaces intact.
//!
//! The checksum and name-hash algorithms are the specification's
//! rotate-right-add accumulators, confirmed to the bit against four
//! measured sets. Up-casing runs through the volume's canonical
//! up-case table — the compressed bytes [`crate::fs::exfat::upcase::table`]
//! carries — decoded once into a flat `u16` map behind a
//! [`std::sync::OnceLock`] (the crate forbids `unsafe`, and a one-time
//! lock is where a 128 KiB decode belongs).
//!
//! Like every `exfat` module, field writes go through the checked
//! [`put_bytes`]-family helpers, failures are [`CoreError`]s naming the
//! offending value, and no non-test code indexes a slice directly.

use std::sync::OnceLock;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::exfat::format::ENTRY_BYTES;
use crate::fs::exfat::get_u16;
use crate::fs::exfat::get_u32;
use crate::fs::exfat::get_u64;
use crate::fs::exfat::put_bytes;
use crate::fs::exfat::put_u16;
use crate::fs::exfat::put_u32;
use crate::fs::exfat::put_u64;
use crate::fs::exfat::upcase;

/// Type code of the leading File entry of a set (spec 7.4).
pub const ENTRY_FILE: u8 = 0x85;

/// The InUse flag of a Directory entry's type byte (spec 7.4, bit 7):
/// `0x85` with the flag set is a live File entry, the same bytes with
/// the flag clear read `0x05` — an entry every reader skips.
pub const ENTRY_IN_USE: u8 = 0x80;

/// Type code of the Stream Extension entry that follows a File entry
/// (spec 7.6).
pub const ENTRY_STREAM: u8 = 0xC0;

/// Type code of the File Name entries at the set tail (spec 7.7).
pub const ENTRY_NAME: u8 = 0xC1;

/// The UTC-offset byte meaning "no offset recorded" — the value the
/// Linux exFAT driver wrote for all three stamps of the measured
/// reference tree, and what [`Stamp::epoch`] carries.
pub const UTC_OFFSET_UNKNOWN: u8 = 0x80;

/// FileAttributes word bits — the MS-DOS meanings the format reuses.
pub const ATTR_READ_ONLY: u16 = 0x0001;
pub const ATTR_HIDDEN: u16 = 0x0002;
pub const ATTR_SYSTEM: u16 = 0x0004;
pub const ATTR_DIRECTORY: u16 = 0x0010;
pub const ATTR_ARCHIVE: u16 = 0x0020;

/// Stream flag: the entry makes claims an allocator could honour
/// (always set on a real stream entry).
pub const STREAM_ALLOC_POSSIBLE: u8 = 0x01;

/// Stream flag: the allocation is one contiguous run and the FAT
/// describes none of it. The pair with [`STREAM_ALLOC_POSSIBLE`] is
/// what this formatter writes for every directory and every non-empty
/// file — the measured reference sets carry 0x03.
pub const STREAM_NO_FAT_CHAIN: u8 = 0x02;

/// Stream flags of an entry with no allocation at all (DataLength 0):
/// allocation is still *possible*, but there is no chain to describe —
/// the shape the mount-created empty file measured (0x01, cluster 0).
pub const STREAM_EMPTY: u8 = STREAM_ALLOC_POSSIBLE;

/// Stream flags of the File Name entries — measured byte 1 = 0x00
/// (allocation is impossible, no chain point follows a name).
pub const NAME_FLAGS: u8 = 0x00;

/// Longest file name, in UTF-16 units (spec 7.7.3: the concatenated
/// name is at most 255 units long).
pub const MAX_NAME_UNITS: usize = 255;

/// UTF-16 units one File Name entry carries (30 bytes = 15 units).
pub const NAME_UNITS_PER_ENTRY: usize = 15;

/// Most File Name entries a set may carry (255 units / 15 per entry,
/// rounded up — the same 17 every reference implementation pins).
pub const MAX_NAME_ENTRIES: usize = 17;

/// Most slots a directory entry set occupies: File + Stream + names.
pub const MAX_SET_LEN: usize = 2 + MAX_NAME_ENTRIES;

// Per-entry field offsets as measured (module docs and tests below).
mod file {
    pub const SECONDARY_COUNT: usize = 1;
    pub const SET_CHECKSUM: usize = 2;
    pub const FILE_ATTRIBUTES: usize = 4;
    pub const CREATE: usize = 8;
    pub const MODIFY: usize = 12;
    pub const ACCESS: usize = 16;
    pub const CREATE_10MS: usize = 20;
    pub const MODIFY_10MS: usize = 21;
    pub const CREATE_OFFSET: usize = 22;
    pub const MODIFY_OFFSET: usize = 23;
    pub const ACCESS_OFFSET: usize = 24;

    /// The byte offsets of the flat entry-set bytes the set checksum
    /// skips: bytes 2..=3 of the *first* 32 bytes of the set.
    pub const CHECKSUM_SKIP: [usize; 2] = [2, 3];
}

mod stream {
    pub const FLAGS: usize = 1;
    pub const NAME_LENGTH: usize = 3;
    pub const NAME_HASH: usize = 4;
    pub const VALID_DATA_LENGTH: usize = 8;
    pub const FIRST_CLUSTER: usize = 20;
    pub const DATA_LENGTH: usize = 24;
}

/// The FileName field of a 0xC1 entry: bytes 2..=32, 15 UTF-16 units.
pub const NAME_FIELD_AT: usize = 2;
pub const NAME_FIELD_BYTES: usize = 30;

/// One of the three stamp triples every File entry carries.
///
/// The 32-bit timestamp is the DOS encoding the FAT timestamps use —
/// the *date* field (year 1980 = 0, 1-based month, day) in the high 16
/// bits, the *time* field (hour, minute, 2-second pairs) below — which
/// is why [`Stamp::from_ymdhms`] delegates its validation to
/// [`crate::fs::fat32::dirent::FatTime::from_ymdhms`]: the two formats
/// stamp byte-identically, so one encoding serves both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// `(date << 16) | time`, both in the DOS field encoding.
    pub date_time: u32,
    /// 10 ms increments beyond the timestamp's whole seconds, 0..=199.
    pub tenths: u8,
    /// UTC offset: [`UTC_OFFSET_UNKNOWN`], or a 7-bit field counting
    /// 15-minute units (the negative band arrives biased by 0x40) —
    /// the byte the measured reference images all carry as 0x80.
    pub utc_offset: u8,
}

impl Stamp {
    /// The stamp of "1980-01-01 00:00:00.000, no UTC offset recorded":
    /// the first moment the format can express, so every stamp stays
    /// deterministic until a caller supplies the real clock — the same
    /// default [`crate::fs::fat32::dirent::FatTime::default`] gives.
    #[must_use]
    pub const fn epoch() -> Self {
        // DOS date 1980-01-01 encodes as (1 << 5) | 1 = 0x21; the epoch
        // carries no time, no seconds and no offset.
        Self {
            date_time: 0x0021_0000,
            tenths: 0,
            utc_offset: UTC_OFFSET_UNKNOWN,
        }
    }

    /// Encode `(year, month, day, hour, minute, second)` local values
    /// into a stamp, tenths zero, UTC offset left unknown.
    ///
    /// Refusals name the offending field: a year above 2107 (the 7-bit
    /// year field runs out), a month outside 1..=12, a day outside the
    /// month's length (leap-corrected), an hour/minute/second outside
    /// its range. A pre-1980 year clamps to the epoch — the field
    /// cannot express earlier moments and a mis-set clock is far
    /// likelier than an intentional lie.
    pub fn from_ymdhms(
        year: u16,
        month: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
    ) -> Result<Self> {
        // The date/time encoding is the DOS one FAT32 already writes, so
        // the validation lives in one place: a second copy drifts.
        let time =
            crate::fs::fat32::dirent::FatTime::from_ymdhms(year, month, day, hour, minute, second)?;
        Ok(Self {
            date_time: (u32::from(time.date) << 16) | u32::from(time.time),
            tenths: 0,
            utc_offset: UTC_OFFSET_UNKNOWN,
        })
    }
}

/// The three stamp triples a File entry carries: when the entry was
/// created, when its contents last changed, and when they were last
/// read. [`Stamps::equal`] fills all three from one value — the shape
/// every create path in this crate uses, and the one the measured
/// reference tree showed (all three triples identical on a fresh mount).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamps {
    /// The create triple.
    pub create: Stamp,
    /// The last-modified triple.
    pub modify: Stamp,
    /// The last-accessed triple (the format defines no 10 ms increment
    /// for it, so its tenth byte is meaningless on disk).
    pub access: Stamp,
}

impl Stamps {
    /// One stamp for all three triples.
    #[must_use]
    pub const fn equal(stamp: Stamp) -> Self {
        Self {
            create: stamp,
            modify: stamp,
            access: stamp,
        }
    }

    /// The epoch stamp in all three triples.
    #[must_use]
    pub const fn epoch() -> Self {
        Self::equal(Stamp::epoch())
    }
}

/// Up-case UTF-16 units through the on-disk up-case table — the
/// comparison the format itself defines (exFAT names are
/// case-insensitive, case-preserved on disk).
#[must_use]
pub fn upcase_units(units: &[u16]) -> Vec<u16> {
    let table = upcase_map();
    units
        .iter()
        .map(|&unit| table.get(usize::from(unit)).copied().unwrap_or(unit))
        .collect()
}

/// The up-cased text form of [`upcase_units`] (lossy when a name carried
/// lone surrogates, which the on-wire rules never produce).
#[must_use]
pub fn upcase_name(name: &str) -> String {
    let units: Vec<u16> = name.encode_utf16().collect();
    String::from_utf16_lossy(&upcase_units(&units))
}

/// The characters the format forbids in a file name (spec 7.7.3's
/// invalid-character table beyond the control band): `"`, `*`, `/`,
/// `:`, `<`, `>`, `?`, `\`, `|`.
const FORBIDDEN_NAME_CHARS: [u16; 9] = [
    0x0022, 0x002A, 0x002F, 0x003A, 0x003C, 0x003E, 0x003F, 0x005C, 0x007C,
];

/// Validate one user-supplied file or directory name (a single path
/// component, already split off the path).
///
/// Refusals (all [`CoreError::invalid`], naming the offending value):
/// an empty name; a name longer than [`MAX_NAME_UNITS`] UTF-16 units; a
/// codepoint below 0x0021 (the control band 0x0000..=0x001F of the
/// invalid-character table); any of [`FORBIDDEN_NAME_CHARS`]; a name
/// made up of nothing but spaces (encodable, but no directory should
/// carry one); and the reserved `.`, `..` names, which belong to
/// directory-linkage semantics, never to a caller (spec 7.7.3: these
/// reserved names shall not be recorded in a FileName field).
pub fn validate_name(name: &str) -> Result<()> {
    let units: Vec<u16> = name.encode_utf16().collect();
    validate_name_units(&units)
}

/// The [`validate_name`] body over already-split UTF-16 units — what
/// [`entry_set`] re-checks against its own [`Plan`] before writing.
fn validate_name_units(units: &[u16]) -> Result<()> {
    if units.is_empty() {
        return Err(CoreError::invalid(
            "an exfat file or directory name is empty".to_string(),
        ));
    }
    if units.len() > MAX_NAME_UNITS {
        return Err(CoreError::invalid(format!(
            "name [{name}] is {} utf-16 units long, the exfat limit is {MAX_NAME_UNITS}",
            units.len(),
            name = String::from_utf16_lossy(units)
        )));
    }
    let text = String::from_utf16_lossy(units);
    if text == "." || text == ".." {
        return Err(CoreError::invalid(
            "'.' and '..' are reserved for directory linkage, not user names".to_string(),
        ));
    }
    if units.iter().all(|&unit| unit == 0x0020) {
        return Err(CoreError::invalid(format!(
            "name [{text}] is nothing but spaces"
        )));
    }
    if units.iter().any(|&unit| unit < 0x0020) {
        let first = units
            .iter()
            .find(|unit| **unit < 0x0020)
            .copied()
            .unwrap_or(0);
        return Err(CoreError::invalid(format!(
            "name [{text}] carries the control codepoint U+{first:04X}, which exfat forbids"
        )));
    }
    for unit in units {
        if FORBIDDEN_NAME_CHARS.contains(unit) {
            let character = char::from_u32(u32::from(*unit)).unwrap_or('?');
            return Err(CoreError::invalid(format!(
                "name [{text}] carries '{character}' which exfat forbids in a file name"
            )));
        }
    }
    Ok(())
}

/// Clear the InUse flag of a set's lead — the first write of the
/// two-phase entry-set creation (both the append path and the
/// stream-rewrite path in [`super::volume::Exfat`]): the whole set goes
/// down while invisible, then the flag is set back with one final lead
/// write. A write torn before that leaves an inactive lead every reader
/// skips (measured: this crate's walker, the kernel driver's
/// `TYPE_DELETED`, `fsck.exfat -n` 1.4.3 exit 0 `clean.`), never the
/// live lead over half a set whose checksum mismatch would refuse the
/// whole directory.
pub fn deactivate(image: &mut [u8; ENTRY_BYTES]) {
    if let Some(first) = image.first_mut() {
        *first &= !ENTRY_IN_USE;
    }
}

/// The checksum of one directory entry set (spec 6.3.3, Figure 2):
/// rotate-right-add over every byte of every entry in set order,
/// skipping bytes 2..=3 of the *first* entry — the bytes the checksum
/// itself is stored in. Confirmed to the bit against the four measured
/// reference sets (tests below).
#[must_use]
pub fn set_checksum(entries: &[[u8; ENTRY_BYTES]]) -> u16 {
    let mut checksum = 0_u16;
    for (index, entry) in entries.iter().enumerate() {
        for (position, byte) in entry.iter().enumerate() {
            if index == 0 && file::CHECKSUM_SKIP.contains(&position) {
                continue;
            }
            // Rotate right exactly one bit: bit 0 folds up into bit 15,
            // keeping the accumulator in 16 bits without masking.
            checksum = checksum.rotate_right(1).wrapping_add(u16::from(*byte));
        }
    }
    checksum
}

/// The UTF-16 name hash a Stream entry stores (spec 7.6.4, Figure 4):
/// rotate-right-add over the little-endian *bytes* of each unit of the
/// up-cased name, low byte first (the spec hashes the name's UTF-16LE
/// byte stream; the measured hashes pinned below come out of that
/// stream one unit's two bytes at a time).
#[must_use]
pub fn name_hash(name_units: &[u16]) -> u16 {
    let mut hash = 0_u16;
    for unit in upcase_units(name_units) {
        hash = hash
            .rotate_right(1)
            .wrapping_add(unit & 0x00FF)
            .rotate_right(1)
            .wrapping_add(unit >> 8);
    }
    hash
}

/// The compressed up-case table decoded to a flat `codepoint ->
/// up-case` map, built at most once per process.
fn upcase_map() -> &'static Vec<u16> {
    static TABLE: OnceLock<Vec<u16>> = OnceLock::new();
    TABLE.get_or_init(|| decode_upcase_table(upcase::table()))
}

/// Decode the compressed table form into the identity-initialised
/// mapping the format defines: a `0xFFFF` marker introduces a run of
/// `count` codepoints that up-case to themselves (the decode skips
/// them), every other unit is the up-case of the codepoint the decode
/// is advancing over.
///
/// The table is a compile-time constant of this crate, so the guards
/// below (checked reads, no slice indexing) exist to keep the decoder
/// total against a future malformed table rather than runtime input;
/// a malformed stream simply stops decoding and leaves the remainder
/// identity-mapped, a shape the measured-hash tests cannot fail to
/// notice.
fn decode_upcase_table(compressed: &[u8]) -> Vec<u16> {
    // Identity everywhere first: any codepoint the instruction stream
    // never mentions up-cases to itself.
    let mut map: Vec<u16> = (0..=u16::MAX).collect();

    let mut at = 0_usize;
    let mut codepoint = 0_usize;
    while at < compressed.len() {
        let Some(unit) = get_u16(compressed, at) else {
            break; // a half-unit tail: stop rather than guess
        };
        if unit != 0xFFFF {
            if let Some(slot) = map.get_mut(codepoint) {
                *slot = unit;
            }
            codepoint = codepoint.saturating_add(1);
            at = at.saturating_add(2);
            continue;
        }
        // The marker's run count follows it; a missing count ends the
        // decode (the canonical table ends on exactly such a trailing
        // marker: "the rest up-cases to itself").
        let Some(count) = get_u16(compressed, at.checked_add(2).unwrap_or(at)) else {
            break;
        };
        codepoint = codepoint.saturating_add(usize::from(count));
        at = at.saturating_add(4);
    }
    map
}

/// A read-back directory entry: everything
/// [`list_dir`](crate::fs::exfat::volume::Exfat::list_dir) reports and
/// everything the create paths' duplicate check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The user-visible name (case-preserved, lossy UTF-16 decode).
    pub name: String,
    /// The FileAttributes word.
    pub attributes: u16,
    /// Whether the entry's directory bit is set.
    pub is_dir: bool,
    /// The Stream entry's DataLength (the allocation's byte size).
    pub size: u64,
    /// First cluster of the data (`0` marks an entry with no
    /// allocation — an empty file).
    pub first_cluster: u32,
    /// How far into the data user data has actually been written.
    pub valid_data_length: u64,
    /// The three stamp triples.
    pub stamps: Stamps,
}

impl DirEntry {
    /// The FileAttributes word this crate writes: [`ATTR_ARCHIVE`] for
    /// a file, [`ATTR_DIRECTORY`] alone for a directory — the exact
    /// words the measured reference sets carry.
    #[must_use]
    pub fn attributes_for(is_dir: bool) -> u16 {
        if is_dir { ATTR_DIRECTORY } else { ATTR_ARCHIVE }
    }
}

/// The planned shape of one new entry set, decided entirely before any
/// byte is written: name, attributes, allocation, stamps.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The name's UTF-16 units (case-preserved as the caller gave it).
    pub name_units: Vec<u16>,
    /// FileAttributes word ([`DirEntry::attributes_for`] covers both
    /// shapes this crate writes; extra bits pass through).
    pub attributes: u16,
    /// Whether the set describes a directory (its stream's
    /// ValidDataLength must equal DataLength then).
    pub is_dir: bool,
    /// First cluster of the allocation, `0` for an empty file.
    pub first_cluster: u32,
    /// User data written so far (`0` for everything this slice
    /// creates — the spec's fresh entry state).
    pub valid_data_length: u64,
    /// The allocation's length in bytes (the file's size, or the
    /// directory's whole allocation).
    pub data_length: u64,
    /// The entry's stamp triples.
    pub stamps: Stamps,
}

impl Plan {
    /// How many 32-byte slots this plan's entry set occupies:
    /// File + Stream + one File Name entry per 15 units of name.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        2 + self.name_units.len().div_ceil(NAME_UNITS_PER_ENTRY)
    }
}

/// Build the full entry set image for `plan`: one File entry, one
/// Stream extension, and enough File Name entries for the name's
/// units, each zero-padded to 32 bytes, in the order File, Stream,
/// Names.
///
/// Refusals (all naming the offending value; refusing here is what
/// keeps the create paths' "nothing was written" promise true): a name
/// that [`validate_name_units`] rejects or exceeds [`MAX_NAME_UNITS`],
/// a set that would exceed [`MAX_SET_LEN`] slots, a directory whose
/// stream lengths disagree, a file whose valid data claims more than
/// its data length, and an allocation claim contradicting the cluster
/// field (data without a cluster, or a cluster below the heap for
/// non-empty data).
pub fn entry_set(plan: &Plan) -> Result<Vec<[u8; ENTRY_BYTES]>> {
    validate_name_units(&plan.name_units)?;
    if plan.name_units.len() > MAX_NAME_UNITS {
        return Err(CoreError::invalid(format!(
            "name of {} utf-16 units exceeds the {MAX_NAME_UNITS} unit exfat limit",
            plan.name_units.len()
        )));
    }
    if plan.entry_count() > MAX_SET_LEN {
        return Err(CoreError::invalid(format!(
            "an entry set of {} slots exceeds the {MAX_SET_LEN} slot limit",
            plan.entry_count()
        )));
    }
    if plan.is_dir && plan.valid_data_length != plan.data_length {
        return Err(CoreError::invalid(format!(
            "directory stream valid length {} disagrees with data length {}",
            plan.valid_data_length, plan.data_length
        )));
    }
    if plan.valid_data_length > plan.data_length {
        return Err(CoreError::invalid(format!(
            "valid data length {} exceeds the {} byte data length",
            plan.valid_data_length, plan.data_length
        )));
    }
    if plan.data_length == 0 && plan.first_cluster != 0 {
        return Err(CoreError::invalid(format!(
            "zero-length data claims first cluster {}",
            plan.first_cluster
        )));
    }
    if plan.data_length > 0 && plan.first_cluster < 2 {
        return Err(CoreError::invalid(format!(
            "{} bytes of data cannot start at cluster {}",
            plan.data_length, plan.first_cluster
        )));
    }

    let name_entries = plan.name_units.len().div_ceil(NAME_UNITS_PER_ENTRY);
    let mut set = vec![[0_u8; ENTRY_BYTES]; 2 + name_entries];

    // --- File directory entry (0x85) -----------------------------------
    let Some(file_entry) = set.first_mut() else {
        return Err(CoreError::invalid(
            "an entry set lost its file entry".to_string(),
        ));
    };
    put_bytes(file_entry, 0, &[ENTRY_FILE])?;
    let secondary = u8::try_from(1 + name_entries).map_err(|_| {
        CoreError::invalid(format!(
            "{name_entries} name entries overflow the byte-wide secondary count"
        ))
    })?;
    put_bytes(file_entry, file::SECONDARY_COUNT, &[secondary])?;
    let attributes = if plan.is_dir {
        plan.attributes | ATTR_DIRECTORY
    } else {
        plan.attributes | ATTR_ARCHIVE
    };
    put_u16(file_entry, file::FILE_ATTRIBUTES, attributes)?;
    put_u32(file_entry, file::CREATE, plan.stamps.create.date_time)?;
    put_u32(file_entry, file::MODIFY, plan.stamps.modify.date_time)?;
    put_u32(file_entry, file::ACCESS, plan.stamps.access.date_time)?;
    put_bytes(file_entry, file::CREATE_10MS, &[plan.stamps.create.tenths])?;
    put_bytes(file_entry, file::MODIFY_10MS, &[plan.stamps.modify.tenths])?;
    put_bytes(
        file_entry,
        file::CREATE_OFFSET,
        &[plan.stamps.create.utc_offset],
    )?;
    put_bytes(
        file_entry,
        file::MODIFY_OFFSET,
        &[plan.stamps.modify.utc_offset],
    )?;
    put_bytes(
        file_entry,
        file::ACCESS_OFFSET,
        &[plan.stamps.access.utc_offset],
    )?;

    // --- Stream extension (0xC0) ----------------------------------------
    let Some(stream_entry) = set.get_mut(1) else {
        return Err(CoreError::invalid(
            "an entry set lost its stream entry".to_string(),
        ));
    };
    put_bytes(stream_entry, 0, &[ENTRY_STREAM])?;
    let stream_flags = if plan.data_length == 0 {
        // Measured shape of an empty file: allocation possible, no
        // chain, no cluster. Directories always carry at least one
        // cluster, so they never take this branch.
        STREAM_EMPTY
    } else {
        // Measured shape of directories and sized files: the run is
        // contiguous and the FAT describes none of it.
        STREAM_ALLOC_POSSIBLE | STREAM_NO_FAT_CHAIN
    };
    put_bytes(stream_entry, stream::FLAGS, &[stream_flags])?;
    let name_length = u8::try_from(plan.name_units.len()).map_err(|_| {
        CoreError::invalid(format!(
            "name length {} overflows the byte-wide NameLength field",
            plan.name_units.len()
        ))
    })?;
    put_bytes(stream_entry, stream::NAME_LENGTH, &[name_length])?;
    put_u16(stream_entry, stream::NAME_HASH, name_hash(&plan.name_units))?;
    put_u64(
        stream_entry,
        stream::VALID_DATA_LENGTH,
        plan.valid_data_length,
    )?;
    put_u32(stream_entry, stream::FIRST_CLUSTER, plan.first_cluster)?;
    put_u64(stream_entry, stream::DATA_LENGTH, plan.data_length)?;

    // --- File Name entries (0xC1) ---------------------------------------
    let mut pieces: Vec<&[u16]> = Vec::with_capacity(name_entries);
    for piece in plan.name_units.chunks(NAME_UNITS_PER_ENTRY) {
        pieces.push(piece);
    }
    for (index, piece) in pieces.iter().enumerate() {
        let Some(entry) = set.get_mut(2 + index) else {
            return Err(CoreError::invalid(format!(
                "name entry {index} lost its slot in a {} slot set",
                set.len()
            )));
        };
        put_bytes(entry, 0, &[ENTRY_NAME])?;
        put_bytes(entry, 1, &[NAME_FLAGS])?;
        let mut field = Vec::with_capacity(NAME_FIELD_BYTES);
        for unit in piece.iter() {
            field.extend_from_slice(&unit.to_le_bytes());
        }
        field.resize(NAME_FIELD_BYTES, 0);
        put_bytes(entry, NAME_FIELD_AT, &field)?;
    }

    // The checksum binds the set and goes in last, after every other
    // byte of the set is final.
    let checksum = set_checksum(&set);
    if let Some(file_entry) = set.first_mut() {
        put_u16(file_entry, file::SET_CHECKSUM, checksum)?;
    }
    Ok(set)
}

/// The 30-byte zero-filled File Name field for one name piece (a
/// test helper today: the create paths write whole sets through
/// [`entry_set`]).
#[cfg(test)]
fn name_piece(unit_piece: &[u16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(NAME_FIELD_BYTES);
    for unit in unit_piece {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.resize(NAME_FIELD_BYTES, 0);
    bytes
}

/// Parse one directory entry set from its slots — the read-back
/// counterpart of [`entry_set`], including both integrity verifications
/// the format defines: the set checksum and the stream name hash.
fn parse_set(entries: &[[u8; ENTRY_BYTES]]) -> Result<DirEntry> {
    let Some(file_entry) = entries.first() else {
        return Err(CoreError::invalid(
            "an entry set needs a 0x85 file entry first".to_string(),
        ));
    };
    if file_entry.first().copied().unwrap_or(0) != ENTRY_FILE {
        return Err(CoreError::invalid(format!(
            "an entry set starts with type byte {lead:#04x}, not the 0x85 file entry",
            lead = file_entry.first().copied().unwrap_or(0)
        )));
    }
    if entries.len() > MAX_SET_LEN {
        return Err(CoreError::invalid(format!(
            "an entry set of {} slots exceeds the {MAX_SET_LEN} slot limit",
            entries.len()
        )));
    }
    let stored_checksum = get_u16(file_entry, file::SET_CHECKSUM).unwrap_or(0);
    let computed_checksum = set_checksum(entries);
    if stored_checksum != computed_checksum {
        return Err(CoreError::invalid(format!(
            "entry set checksum reads {stored_checksum:#06x} but the set hashes to \
             {computed_checksum:#06x}"
        )));
    }
    let attributes = get_u16(file_entry, file::FILE_ATTRIBUTES).unwrap_or(0);
    let stamps = Stamps {
        create: stamp_of(
            file_entry,
            file::CREATE,
            file::CREATE_10MS,
            file::CREATE_OFFSET,
        ),
        modify: stamp_of(
            file_entry,
            file::MODIFY,
            file::MODIFY_10MS,
            file::MODIFY_OFFSET,
        ),
        access: Stamp {
            date_time: get_u32(file_entry, file::ACCESS).unwrap_or(0),
            // The format defines no 10 ms increment for access.
            tenths: 0,
            utc_offset: file_entry.get(file::ACCESS_OFFSET).copied().unwrap_or(0),
        },
    };

    let Some(stream_entry) = entries.get(1) else {
        return Err(CoreError::invalid(
            "an entry set has no 0xC0 stream entry".to_string(),
        ));
    };
    if stream_entry.first().copied().unwrap_or(0) != ENTRY_STREAM {
        return Err(CoreError::invalid(format!(
            "a set's second entry reads type byte {lead:#04x}, not 0xC0",
            lead = stream_entry.first().copied().unwrap_or(0)
        )));
    }
    let name_length = usize::from(stream_entry.get(stream::NAME_LENGTH).copied().unwrap_or(0));
    if !(1..=MAX_NAME_UNITS).contains(&name_length) {
        return Err(CoreError::invalid(format!(
            "stream NameLength {name_length} is not within 1..={MAX_NAME_UNITS}"
        )));
    }
    let mut units = Vec::with_capacity(name_length);
    for entry in entries.iter().skip(2) {
        for pair in entry
            .get(NAME_FIELD_AT..NAME_FIELD_AT + NAME_FIELD_BYTES)
            .unwrap_or(&[])
            .as_chunks::<2>()
            .0
        {
            units.push(u16::from(pair[0]) | (u16::from(pair[1]) << 8));
            if units.len() == name_length {
                break;
            }
        }
        if units.len() == name_length {
            break;
        }
    }
    if units.len() != name_length {
        return Err(CoreError::invalid(format!(
            "the set carries {} name units for NameLength {name_length}",
            units.len()
        )));
    }
    let stored_hash = get_u16(stream_entry, stream::NAME_HASH).unwrap_or(0);
    let computed_hash = name_hash(&units);
    if stored_hash != computed_hash {
        return Err(CoreError::invalid(format!(
            "stream name hash reads {stored_hash:#06x} but the name [{name}] hashes to \
             {computed_hash:#06x}",
            name = String::from_utf16_lossy(&units)
        )));
    }
    Ok(DirEntry {
        name: String::from_utf16_lossy(&units),
        attributes,
        is_dir: attributes & ATTR_DIRECTORY != 0,
        size: get_u64(stream_entry, stream::DATA_LENGTH).unwrap_or(0),
        first_cluster: get_u32(stream_entry, stream::FIRST_CLUSTER).unwrap_or(0),
        valid_data_length: get_u64(stream_entry, stream::VALID_DATA_LENGTH).unwrap_or(0),
        stamps,
    })
}

/// Recover one stamp triple out of a date-time field, its 10 ms byte
/// and its UTC-offset byte.
fn stamp_of(entry: &[u8], timestamp_at: usize, tenths_at: usize, offset_at: usize) -> Stamp {
    Stamp {
        date_time: get_u32(entry, timestamp_at).unwrap_or(0),
        tenths: entry.get(tenths_at).copied().unwrap_or(0),
        utc_offset: entry.get(offset_at).copied().unwrap_or(0),
    }
}

/// One directory, already reduced to its slots: the entries read back
/// in on-disk order, the slot where each entry's set begins, and the
/// first end-of-directory slot — which every create path of this slice
/// appends at.
#[derive(Debug, Clone)]
pub struct DirListing {
    /// Real entries, in the order the volume stores them.
    pub entries: Vec<DirEntry>,
    /// Slot index where each of `entries`' sets begins, in the same
    /// order (parallel to `entries`).
    pub set_starts: Vec<usize>,
    /// Slot index of the first end-of-directory marker.
    pub terminator_slot: usize,
    /// Slots the directory's current allocation holds in total.
    pub total_slots: usize,
}

/// Walk a directory's bytes into a [`DirListing`].
///
/// Scan rules, read from the spec's directory-structure sections: the
/// first `0x00` slot is an end-of-directory marker and *stops* the
/// walk (everything after a marker is required to be markers too); a
/// `0x85` slot opens an entry set of `1 + SecondaryCount` slots, and a
/// set missing its declared slots is corrupt, refused with both
/// numbers named; any other slot — this directory's own reserved
/// system entries (0x81 bitmap, 0x82 up-case, 0x83 label), the 0x20
/// volume-GUID shape `mkfs` leaves behind, vendor entries, deleted
/// leads below 0x80, stray 0xC0/0xC1 secondaries — is skipped one slot
/// at a time. That is what keeps the root's system entries out of a
/// listing (and out of the way of the append position) without any
/// list of reserved types.
///
/// `directory` must slice into whole 32-byte slots, which every cluster
/// size this crate writes guarantees (a foreign, smaller-than-32-byte
///-cluster volume is refused with the byte count named).
pub fn parse_dir_listing(directory: &[u8]) -> Result<DirListing> {
    if !directory.len().is_multiple_of(ENTRY_BYTES) {
        return Err(CoreError::invalid(format!(
            "directory bytes {} are not a whole number of 32-byte slots",
            directory.len()
        )));
    }
    let slots = directory.len() / ENTRY_BYTES;
    let mut listing = DirListing {
        entries: Vec::new(),
        set_starts: Vec::new(),
        terminator_slot: slots,
        total_slots: slots,
    };

    let mut slot = 0_usize;
    while slot < slots {
        let window = directory
            .get(slot * ENTRY_BYTES..(slot + 1) * ENTRY_BYTES)
            .ok_or_else(|| CoreError::invalid(format!("directory slot {slot} lost its window")))?;
        let lead = window.first().copied().unwrap_or(0);
        if lead == 0x00 {
            listing.terminator_slot = slot;
            break;
        }
        if lead != ENTRY_FILE {
            // Unused/deleted slots (below 0x80) and every recognized
            // but uninteresting single-slot entry: skipped exactly one
            // slot each.
            slot += 1;
            continue;
        }
        let secondary = usize::from(window.get(1).copied().unwrap_or(0));
        if secondary + 1 > MAX_SET_LEN {
            return Err(CoreError::invalid(format!(
                "the 0x85 entry at slot {slot} claims {secondary} secondaries, beyond the \
                 {MAX_SET_LEN} slot set limit"
            )));
        }
        let set_len = secondary + 1;
        let mut set = Vec::with_capacity(set_len);
        for step in 0..set_len {
            let Some(bytes) =
                directory.get((slot + step) * ENTRY_BYTES..(slot + step + 1) * ENTRY_BYTES)
            else {
                return Err(CoreError::invalid(format!(
                    "the entry set at slot {slot} claims {set_len} slots but the directory \
                     holds {slots}"
                )));
            };
            let Ok(image) = <[u8; ENTRY_BYTES]>::try_from(bytes) else {
                return Err(CoreError::invalid(format!(
                    "the entry set slot {} lost its 32-byte window",
                    slot + step
                )));
            };
            set.push(image);
        }
        listing.entries.push(parse_set(&set)?);
        listing.set_starts.push(slot);
        slot += set_len;
    }
    Ok(listing)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The measured stamp triple of the reference tree: 2026-10-31
    /// 20:34:56 local (DOS stamp 0x5D5FA45C), 1480 ms beyond the whole
    /// second (10 ms increment 148 = 0x94), no UTC offset recorded
    /// (0x80) — read back out of the reference image's `refdir` set.
    const MEASURED_STAMP: Stamp = Stamp {
        date_time: 0x5D5F_A45C,
        tenths: 0x94,
        utc_offset: 0x80,
    };

    /// A `Plan` equal to the reference tree's `refdir` entry. The
    /// reference bytes were produced by: `mkfs.exfat` 1.4.3 formatting
    /// a 64 MiB image, `losetup --direct-io=off` + `mount -t exfat` in
    /// a privileged container, `mkdir refdir` + three files, `umount`,
    /// then `dd` of the root cluster out of the image.
    fn refdir_plan() -> Plan {
        Plan {
            name_units: "refdir".encode_utf16().collect(),
            attributes: ATTR_DIRECTORY,
            is_dir: true,
            first_cluster: 6,
            valid_data_length: 4096,
            data_length: 4096,
            stamps: Stamps::equal(MEASURED_STAMP),
        }
    }

    #[test]
    fn a_directory_set_matches_the_measured_reference_bytes() {
        let set = entry_set(&refdir_plan()).expect("the reference plan builds");
        assert_eq!(set.len(), 3, "file + stream + one name entry");
        let file = set.first().expect("the file entry exists");
        assert_eq!(file[0], 0x85);
        assert_eq!(file[1], 0x02, "stream + one name entry");
        assert_eq!(
            file.get(2..4),
            Some(&[0x98_u8, 0x8E][..]),
            "the measured set checksum 0x8E98 (little-endian bytes)"
        );
        assert_eq!(
            file.get(4..6),
            Some(&[0x10_u8, 0x00][..]),
            "FileAttributes: directory, no archive"
        );
        for at in [6_usize, 25] {
            assert_eq!(
                file.get(at..at + 2),
                Some(&[0_u8, 0][..]),
                "the reserved bytes at {at} stay zero"
            );
        }
        assert_eq!(
            file.get(8..12),
            Some(&[0x5C_u8, 0xA4, 0x5F, 0x5D][..]),
            "create 2026-10-31 20:34:56"
        );
        assert_eq!(
            file.get(12..16),
            Some(&[0x5C_u8, 0xA4, 0x5F, 0x5D][..]),
            "last modified"
        );
        assert_eq!(
            file.get(16..20),
            Some(&[0x5C_u8, 0xA4, 0x5F, 0x5D][..]),
            "last accessed"
        );
        assert_eq!(
            file.get(20..22),
            Some(&[0x94_u8, 0x94][..]),
            "create and modify 10 ms = 1480"
        );
        assert_eq!(
            file.get(22..25),
            Some(&[0x80_u8, 0x80, 0x80][..]),
            "all three UTC offsets unknown"
        );
        let stream: [u8; 32] = [
            0xC0, 0x03, 0x00, 0x06, 0xF4, 0xF8, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            set.get(1),
            Some(&stream),
            "flags 0x03, name length 6, hash 0xF8F4, valid == data == one cluster, cluster 6"
        );
        let name: [u8; 32] = [
            0xC1, 0x00, 0x72, 0x00, 0x65, 0x00, 0x66, 0x00, 0x64, 0x00, 0x69, 0x00, 0x72, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            set.get(2),
            Some(&name),
            "flags byte 0x00 and the case-preserved name"
        );
    }

    #[test]
    fn a_file_set_matches_the_measured_reference_bytes() {
        let plan = Plan {
            name_units: "File.TXT".encode_utf16().collect(),
            attributes: ATTR_ARCHIVE,
            is_dir: false,
            first_cluster: 7,
            valid_data_length: 12,
            data_length: 12,
            stamps: Stamps::equal(MEASURED_STAMP),
        };
        let set = entry_set(&plan).expect("builds");
        assert_eq!(set.len(), 3);
        let file = set.first().expect("file entry");
        assert_eq!(file[0], 0x85);
        assert_eq!(
            file.get(2..4),
            Some(&[0x86_u8, 0x5D][..]),
            "the measured checksum 0x5D86 (little-endian bytes)"
        );
        assert_eq!(
            file.get(4..6),
            Some(&[0x20_u8, 0x00][..]),
            "FileAttributes: archive"
        );
        let stream: [u8; 32] = [
            0xC0, 0x03, 0x00, 0x08, 0x0C, 0x2B, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            set.get(1),
            Some(&stream),
            "hash 0x2B0C, valid == data == 12 for the written reference file, cluster 7"
        );
        assert_eq!(
            set.get(2).and_then(|name| name.get(2..6)),
            Some(&[0x46_u8, 0x00, 0x69, 0x00][..]),
            "F, i — the name field starts with the name itself"
        );
    }

    #[test]
    fn an_empty_file_carries_no_cluster_and_the_measured_stream_flags() {
        // Measured from the mount-created `empty` reference file: stream
        // flags 0x01, FirstCluster 0, both lengths 0.
        let plan = Plan {
            name_units: "empty".encode_utf16().collect(),
            attributes: ATTR_ARCHIVE,
            is_dir: false,
            first_cluster: 0,
            valid_data_length: 0,
            data_length: 0,
            stamps: Stamps::equal(MEASURED_STAMP),
        };
        let set = entry_set(&plan).expect("builds");
        let stream = set.get(1).expect("stream entry");
        assert_eq!(stream.first().copied(), Some(ENTRY_STREAM));
        assert_eq!(stream[1], 0x01, "no chain when there is no allocation");
        assert_eq!(stream[3], 5, "name length 5");
        assert_eq!(
            stream.get(4..6),
            Some(&[0xBA_u8, 0x3C][..]),
            "the measured name hash of 'empty', 0x3CBA (little-endian bytes)"
        );
        assert_eq!(
            stream.get(8..16),
            Some(&[0_u8; 8][..]),
            "valid data length 0"
        );
        assert_eq!(
            stream.get(16..20),
            Some(&[0_u8; 4][..]),
            "reserved window zero"
        );
        assert_eq!(stream.get(20..24), Some(&[0_u8; 4][..]), "first cluster 0");
        assert_eq!(stream.get(24..32), Some(&[0_u8; 8][..]), "data length 0");
        assert_eq!(
            set.first().and_then(|file| file.get(2..4)),
            Some(&[0x0A_u8, 0x3F][..]),
            "the measured checksum 0x3F0A"
        );
    }

    #[test]
    fn a_fresh_create_keeps_valid_data_length_zero() {
        // `create_file` writes DataLength = size but ValidDataLength 0 —
        // the spec's "created, not yet written" state (section 8.1's
        // write ordering); the same entry written *after* filling the
        // file pins valid == data.
        let mut plan = Plan {
            name_units: "File.TXT".encode_utf16().collect(),
            attributes: ATTR_ARCHIVE,
            is_dir: false,
            first_cluster: 7,
            valid_data_length: 0,
            data_length: 12,
            stamps: Stamps::equal(MEASURED_STAMP),
        };
        let set = entry_set(&plan).expect("builds");
        let stream = set.get(1).expect("stream entry");
        assert_eq!(stream.get(8..16), Some(&[0_u8; 8][..]), "valid stays 0");
        plan.valid_data_length = 12;
        let set_written = entry_set(&plan).expect("builds");
        let expected = 12_u64.to_le_bytes();
        assert_eq!(
            set_written.get(1).and_then(|stream| stream.get(8..16)),
            Some(&expected[..]),
            "the written pin carries valid == data"
        );
    }

    #[test]
    fn a_name_with_a_space_hashes_and_stores_like_the_measured_set() {
        // `mixed Case.txt` from the reference: 14 units, hash 0xB1E1,
        // valid == data == 4, first cluster 8.
        let plan = Plan {
            name_units: "mixed Case.txt".encode_utf16().collect(),
            attributes: ATTR_ARCHIVE,
            is_dir: false,
            first_cluster: 8,
            valid_data_length: 4,
            data_length: 4,
            stamps: Stamps::equal(MEASURED_STAMP),
        };
        let set = entry_set(&plan).expect("builds");
        assert_eq!(set.len(), 3);
        assert_eq!(
            set.get(1).and_then(|s| s.get(4..6)),
            Some(&[0xE1_u8, 0xB1][..]),
            "the measured name hash 0xB1E1 (little-endian bytes)"
        );
        let name_bytes = set
            .get(2)
            .and_then(|name| name.get(NAME_FIELD_AT..NAME_FIELD_AT + 2 * 14))
            .expect("the 14-unit field");
        let expected: Vec<u8> = "mixed Case.txt"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(name_bytes, &expected, "interior space and case preserved");
        assert_eq!(
            set[2][1], NAME_FLAGS,
            "the name entry flags byte stays 0x00"
        );
        assert_eq!(
            set.first().and_then(|f| f.get(2..4)),
            Some(&[0xB4_u8, 0x80][..]),
            "the measured checksum 0x80B4 (little-endian bytes)"
        );
    }

    #[test]
    fn the_set_checksum_matches_all_measured_sets() {
        assert_eq!(
            set_checksum(&entry_set(&refdir_plan()).expect("builds")),
            0x8E98
        );
        let file_set = entry_set(&Plan {
            name_units: "File.TXT".encode_utf16().collect(),
            attributes: ATTR_ARCHIVE,
            is_dir: false,
            first_cluster: 7,
            valid_data_length: 12,
            data_length: 12,
            stamps: Stamps::equal(MEASURED_STAMP),
        })
        .expect("builds");
        assert_eq!(set_checksum(&file_set), 0x5D86);
        let empty_set = entry_set(&Plan {
            name_units: "empty".encode_utf16().collect(),
            attributes: ATTR_ARCHIVE,
            is_dir: false,
            first_cluster: 0,
            valid_data_length: 0,
            data_length: 0,
            stamps: Stamps::equal(MEASURED_STAMP),
        })
        .expect("builds");
        assert_eq!(set_checksum(&empty_set), 0x3F0A);
    }

    #[test]
    fn set_checksum_skips_only_bytes_two_and_three_of_the_first_entry() {
        // The skipped bytes cannot affect the result: garbage there
        // must not move the checksum.
        let set = entry_set(&refdir_plan()).expect("builds");
        let checksum = set_checksum(&set);
        let mut damaged = set.clone();
        damaged[0][2] = 0xFF;
        damaged[0][3] = 0xEE;
        assert_eq!(set_checksum(&damaged), checksum);
        // Bytes 4 and 5 DO affect it (a positive control).
        let mut elsewhere = set.clone();
        elsewhere[0][4] ^= 0x01;
        assert_ne!(set_checksum(&elsewhere), checksum);
    }

    #[test]
    fn name_hashes_match_the_measured_values() {
        // All four from the mount-created reference tree (docker +
        // losetup + mount + dd, the pins' comments trace provenance).
        assert_eq!(
            name_hash(&"File.TXT".encode_utf16().collect::<Vec<_>>()),
            0x2B0C
        );
        assert_eq!(
            name_hash(&"refdir".encode_utf16().collect::<Vec<_>>()),
            0xF8F4
        );
        assert_eq!(
            name_hash(&"mixed Case.txt".encode_utf16().collect::<Vec<_>>()),
            0xB1E1
        );
        assert_eq!(
            name_hash(&"empty".encode_utf16().collect::<Vec<_>>()),
            0x3CBA
        );
    }

    #[test]
    fn name_hash_is_case_insensitive_just_like_the_format() {
        // exFAT compares names up-cased; the hash must agree for a name
        // typed in any case.
        assert_eq!(
            name_hash(&"FILE.txt".encode_utf16().collect::<Vec<_>>()),
            name_hash(&"file.TXT".encode_utf16().collect::<Vec<_>>())
        );
    }

    #[test]
    fn upcase_runs_through_the_on_disk_table() {
        // Mappings of the canonical table itself (read out of the
        // shipped instruction stream; the measured hashes above check
        // the ASCII band end-to-end).
        assert_eq!(upcase_units(&[0x0061]), &[0x0041], "a to A");
        assert_eq!(upcase_units(&[0x00E0]), &[0x00C0], "a-grave to A-grave");
        assert_eq!(upcase_units(&[0x00DF]), &[0x00DF], "sharp s maps to itself");
        assert_eq!(
            upcase_units(&[0x0253]),
            &[0x0181],
            "a compressed-table mapping"
        );
        assert_eq!(upcase_units(&[0x0254]), &[0x0186], "and its neighbour");
        assert_eq!(
            upcase_units(&[0x1E9B]),
            &[0x1E9B],
            "identity beyond the mandatory band"
        );
        // One decode covers every codepoint once (identity in the gaps).
        assert_eq!(
            upcase_units(&[0x0000, 0xFFFF, 0x0080]),
            &[0x0000, 0xFFFF, 0x0080]
        );
    }

    #[test]
    fn validate_name_takes_legal_names_and_refuses_the_rest() {
        // Longest legal: exactly 255 units — seventeen name entries.
        validate_name(&"a".repeat(255)).expect("255 units fit");
        // One unit too many.
        let error = validate_name(&"a".repeat(256)).expect_err("refused");
        assert!(error.to_string().contains("256"), "{error}");
        // The forbidden codepoints, each named in the refusal.
        for bad in ['\\', '/', ':', '*', '?', '"', '<', '>', '|'] {
            let error = validate_name(&format!("a{bad}b")).expect_err("refused");
            assert!(error.to_string().contains(bad), "{error}");
        }
        // Controls below U+0021.
        let error = validate_name("a\u{0001}b").expect_err("control refused");
        assert!(error.to_string().contains("control"), "{error}");
        // Spaces-only names.
        let error = validate_name("   ").expect_err("refused");
        assert!(error.to_string().contains("spaces"), "{error}");
        // Reserved dot names.
        for bad in [".", ".."] {
            let error = validate_name(bad).expect_err("refused");
            assert!(error.to_string().contains("reserved"), "{error}");
        }
        // Interior and trailing spaces are legal — exFAT has no short
        // name field that would lose them (kept case-preserved, spec 7.7).
        validate_name("mixed Case.txt").expect("legal");
        validate_name("trailing ").expect("legal");
    }

    #[test]
    fn entry_set_refuses_names_and_lengths_the_format_cannot_store() {
        let mut plan = refdir_plan();
        plan.name_units.clear();
        let error = entry_set(&plan).expect_err("empty name");
        assert!(error.to_string().contains("empty"), "{error}");

        plan.name_units = vec![0x61; MAX_NAME_UNITS];
        entry_set(&plan).expect("255 units build 17 name entries + 2");
        assert_eq!(plan.entry_count(), 19, "2 + 255/15 up");
        assert_eq!(MAX_SET_LEN, 19);

        plan.name_units = vec![0x61; MAX_NAME_UNITS + 1];
        let error = entry_set(&plan).expect_err("256 units refuse");
        assert!(error.to_string().contains("256"), "{error}");
    }

    #[test]
    fn entry_set_refuses_inconsistent_streams() {
        let mut plan = refdir_plan();
        plan.valid_data_length = 4095; // a directory must claim whole clusters
        let error = entry_set(&plan).expect_err("dir valid != data");
        assert!(error.to_string().contains("disagree"), "{error}");

        let mut file = Plan {
            name_units: "big".encode_utf16().collect(),
            attributes: ATTR_ARCHIVE,
            is_dir: false,
            first_cluster: 0,
            valid_data_length: 1,
            data_length: 1,
            stamps: Stamps::equal(Stamp::epoch()),
        };
        let error = entry_set(&file).expect_err("data without a cluster");
        assert!(error.to_string().contains("cannot start"), "{error}");

        file.data_length = 512;
        file.first_cluster = 1;
        let error = entry_set(&file).expect_err("cluster below the heap");
        assert!(error.to_string().contains("cluster 1"), "{error}");

        file.data_length = 4;
        file.first_cluster = 3;
        file.valid_data_length = 5; // beyond the 4-byte data length
        let error = entry_set(&file).expect_err("valid beyond data");
        assert!(error.to_string().contains("exceeds"), "{error}");
    }

    #[test]
    fn a_parsed_directory_round_trips_every_entry_field() {
        // The refdir set plus the terminator the on-disk layout keeps.
        let set = entry_set(&refdir_plan()).expect("builds");
        let mut directory = Vec::new();
        for entry in &set {
            directory.extend_from_slice(entry);
        }
        directory.extend_from_slice(&[0_u8; ENTRY_BYTES]);
        directory.extend_from_slice(&[0_u8; ENTRY_BYTES]);

        let listing = parse_dir_listing(&directory).expect("parses");
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.set_starts, vec![0]);
        assert_eq!(listing.terminator_slot, 3, "the marker after the set");
        assert_eq!(listing.total_slots, 5);
        let read = listing.entries.first().expect("one entry");
        assert_eq!(read.name, "refdir");
        assert!(read.is_dir);
        assert_eq!(read.attributes, ATTR_DIRECTORY);
        assert_eq!(read.size, 4096);
        assert_eq!(read.first_cluster, 6);
        assert_eq!(read.valid_data_length, 4096);
        // The access triple reads back with tenths 0 — the format has
        // no 10 ms increment for accesses (only create and modify do).
        assert_eq!(read.stamps.create, MEASURED_STAMP);
        assert_eq!(read.stamps.modify, MEASURED_STAMP);
        assert!(read.stamps.access.date_time == MEASURED_STAMP.date_time);
        assert_eq!(read.stamps.access.tenths, 0);
        assert_eq!(read.stamps.access.utc_offset, MEASURED_STAMP.utc_offset);
    }

    #[test]
    fn the_parse_walk_skips_system_and_deleted_slots() {
        // A root-shaped directory: 0x83 label, 0x81 bitmap, 0x82
        // up-case, mkfs's 0x20 placeholder, a deleted lead, then a real
        // set, then the marker.
        let set = entry_set(&refdir_plan()).expect("builds");
        let mut directory = Vec::new();
        let mut label_slot = [0_u8; ENTRY_BYTES];
        label_slot[0] = 0x83;
        label_slot[1] = 3;
        directory.extend_from_slice(&label_slot);
        let mut bitmap_slot = [0_u8; ENTRY_BYTES];
        bitmap_slot[0] = 0x81;
        directory.extend_from_slice(&bitmap_slot);
        let mut upcase_slot = [0_u8; ENTRY_BYTES];
        upcase_slot[0] = 0x82;
        directory.extend_from_slice(&upcase_slot);
        let mut guid_slot = [0_u8; ENTRY_BYTES];
        guid_slot[0] = 0x20; // mkfs's placeholder: benign, unknown-origin
        directory.extend_from_slice(&guid_slot);
        let mut deleted_slot = [0_u8; ENTRY_BYTES];
        deleted_slot[0] = 0x05; // a deleted file lead (InUse cleared)
        directory.extend_from_slice(&deleted_slot);
        for entry in &set {
            directory.extend_from_slice(entry);
        }
        directory.extend_from_slice(&[0_u8; ENTRY_BYTES]);

        let listing = parse_dir_listing(&directory).expect("parses");
        assert_eq!(listing.entries.len(), 1, "only the file set lists");
        assert_eq!(
            listing.entries.first().map(|e| e.name.clone()),
            Some("refdir".to_string())
        );
        // Slots 0..=4 are the skipped system and deleted leads, the set
        // occupies 5..=7, and slot 8 is the marker.
        assert_eq!(listing.set_starts, vec![5]);
        assert_eq!(listing.terminator_slot, 8);
    }

    #[test]
    fn a_hash_mismatch_is_refused() {
        // The integrity check the format mandates: a stream hash that
        // does not match the name refuses (both numbers named).
        let set = entry_set(&refdir_plan()).expect("builds");
        let mut directory = Vec::new();
        for entry in &set {
            directory.extend_from_slice(entry);
        }
        directory.extend_from_slice(&[0_u8; ENTRY_BYTES]);
        // Flip one bit of the stored hash (offset 5 of the stream).
        let at = ENTRY_BYTES + 5;
        directory[at] ^= 0x01;
        let error = parse_dir_listing(&directory).expect_err("bad hash");
        assert!(error.to_string().contains("hashes to"), "{error}");
    }

    #[test]
    fn a_corrupt_secondary_entry_fails_the_set_checksum_gate() {
        // The gate every directory walk runs: slot 0's SetChecksum must
        // cover the whole set. Flipping a bit inside the stream entry
        // leaves the name hash intact, so only the checksum can refuse.
        let set = entry_set(&refdir_plan()).expect("builds");
        let mut directory = Vec::new();
        for entry in &set {
            directory.extend_from_slice(entry);
        }
        directory.extend_from_slice(&[0_u8; ENTRY_BYTES]);
        let at = ENTRY_BYTES + 8;
        directory[at] ^= 0x01;
        let error = parse_dir_listing(&directory).expect_err("bad set checksum");
        assert!(error.to_string().contains("checksum"), "{error}");
    }

    #[test]
    fn distinct_stamps_land_in_their_own_fields() {
        // All three measured stamps were equal, so swapping the fields
        // passed every other test; distinct values pin the offsets.
        let mut plan = refdir_plan();
        plan.stamps = Stamps {
            create: Stamp {
                date_time: 0x1111_2222,
                tenths: 0x33,
                utc_offset: UTC_OFFSET_UNKNOWN,
            },
            modify: Stamp {
                date_time: 0x3333_4444,
                tenths: 0x55,
                utc_offset: UTC_OFFSET_UNKNOWN,
            },
            access: Stamp {
                date_time: 0x5555_6666,
                tenths: 0x77,
                utc_offset: UTC_OFFSET_UNKNOWN,
            },
        };
        let set = entry_set(&plan).expect("the plan builds");
        let file = set.first().expect("the file entry exists");
        assert_eq!(
            file.get(8..12),
            Some(&0x1111_2222_u32.to_le_bytes()[..]),
            "create"
        );
        assert_eq!(
            file.get(12..16),
            Some(&0x3333_4444_u32.to_le_bytes()[..]),
            "modified"
        );
        assert_eq!(
            file.get(16..20),
            Some(&0x5555_6666_u32.to_le_bytes()[..]),
            "accessed"
        );
        assert_eq!(
            file.get(20..22),
            Some(&[0x33_u8, 0x55][..]),
            "create and modify 10 ms; access has no such field"
        );
    }

    #[test]
    fn a_truncated_set_is_refused_with_both_numbers() {
        // File + stream + one name piece, then the bytes stop: the set
        // names two more name entries that never made it to the
        // directory (the secondary count claims 5 slots, only 3 hold).
        let mut plan = refdir_plan();
        plan.name_units = vec![0x61; 31]; // 2 + ceil(31/15) = 5 slots
        let set = entry_set(&plan).expect("builds");
        assert_eq!(set.len(), 5);
        let mut directory = Vec::new();
        for entry in set.iter().take(3) {
            directory.extend_from_slice(entry);
        }
        let error = parse_dir_listing(&directory).expect_err("truncated");
        assert!(error.to_string().contains("claims"), "{error}");
        assert!(error.to_string().contains("3"), "{error}");
    }

    #[test]
    fn a_non_slot_multiple_directory_is_refused() {
        let error = parse_dir_listing(&[0_u8; 33]).expect_err("one byte over a slot");
        assert!(error.to_string().contains("32-byte slots"), "{error}");
    }

    #[test]
    fn name_pieces_fill_their_field_to_thirty_bytes() {
        let units: Vec<u16> = b"ab".iter().map(|&b| u16::from(b)).collect();
        let piece = name_piece(&units);
        assert_eq!(piece[0], b'a');
        assert_eq!(piece[1], 0);
        assert_eq!(piece[2], b'b');
        assert_eq!(piece[3], 0);
        assert_eq!(&piece[4..], &[0_u8; 26], "the unused units stay zero");
    }

    #[test]
    fn stamps_encode_the_dos_fields_and_clamp_pre_epoch() {
        // The same encoding the FAT stamps use, pinned against the
        // reference: 2026-10-31 20:34:56 -> 0x5D5F_A45C, 1480 ms beyond
        // the second in the separate 10 ms byte.
        let stamp = Stamp::from_ymdhms(2026, 10, 31, 20, 34, 56).expect("valid");
        assert_eq!(stamp.date_time, 0x5D5F_A45C);
        assert_eq!(stamp.tenths, 0);
        assert_eq!(stamp.utc_offset, UTC_OFFSET_UNKNOWN);
        assert_eq!(
            Stamp::from_ymdhms(1979, 12, 31, 23, 59, 59)
                .expect("clamps")
                .date_time,
            0x0021_0000
        );
        let error = Stamp::from_ymdhms(2108, 1, 1, 0, 0, 0).expect_err("year");
        assert!(error.to_string().contains("2108"), "{error}");
        let error = Stamp::from_ymdhms(2026, 13, 1, 0, 0, 0).expect_err("month");
        assert!(error.to_string().contains("13"), "{error}");
        let error = Stamp::from_ymdhms(2026, 2, 30, 0, 0, 0).expect_err("day");
        assert!(error.to_string().contains("30"), "{error}");
        let error = Stamp::from_ymdhms(2026, 1, 1, 24, 0, 0).expect_err("hour");
        assert!(error.to_string().contains("24"), "{error}");
        let error = Stamp::from_ymdhms(2026, 1, 1, 0, 60, 0).expect_err("minute");
        assert!(error.to_string().contains("60"), "{error}");
        // The leap day of a leap year exists (day validation is
        // leap-corrected, like the FAT stamps).
        Stamp::from_ymdhms(2028, 2, 29, 12, 0, 0).expect("2028 is a leap year");
        let error = Stamp::from_ymdhms(2026, 2, 29, 0, 0, 0).expect_err("not a leap year");
        assert!(error.to_string().contains("29"), "{error}");
    }
}
