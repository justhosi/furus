//! Who supplies the bytes the copy walks: a path-addressed view over
//! one ISO or UDF tree.
//!
//! [`Source`] is deliberately narrow — root listing, children of one
//! directory, an entry's name/kind/size, and a chunked read of a
//! file's bytes — because that is all [`walk`](super::walk) needs.
//! Paths are stacks of raw name bytes (`&[Vec<u8>]`, relative to the
//! root): byte stacks round-trip UDF's decoded names exactly, while
//! the ISO adapter renders the reader's `/`-separated path form from
//! them (see [`IsoSource`] for that fidelity boundary).
//!
//! Metadata rides the listings too: POSIX modes and UTC stamps where
//! the reader has them (ISO `PX`/`TF`; UDF permissions and recording
//! dates), plus symlink targets (`SL` on ISO, path components on UDF).
//! An entry the adapters cannot size as data still refuses here,
//! before any byte moves, instead of copying something wrong.

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crate::error::CoreError;
use crate::error::Result;
use crate::iso::IsoReader;
use crate::iso::rock::RockTime;
use crate::udf::UdfReader;

/// One listed entry: name, kind, size, metadata and link target.
/// Ownership never rides along (needs privileges — see
/// [`DestDir::apply_metadata`](super::DestDir::apply_metadata)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// File name as stored: raw identifier bytes on ISO
    /// ([`file_name`](crate::iso::reader::Entry::file_name)), UTF-8 on
    /// UDF.
    pub name: Vec<u8>,
    /// True for directories. Symlinks never read `true` here for
    /// copying purposes: even a symlink in a directory slot is treated
    /// as a link, never descended into (see [`walk`](super::walk)).
    pub is_dir: bool,
    /// File size in bytes; 0 for directories and for symlinks (a link
    /// costs no bytes — a dereferenced link's size is resolved during
    /// the walk, not here).
    pub size: u64,
    /// POSIX mode from `PX` (file type bits included — the destination
    /// masks) or from the UDF permissions word (masked to `0o7777`);
    /// `None` where the record carries no `PX` (ISO).
    pub mode: Option<u32>,
    /// Modification time from `TF` (ISO) or the UDF modification date,
    /// converted to UTC; `None` where the record carries none or where
    /// conversion refuses.
    pub modified: Option<SystemTime>,
    /// Last-access time, converted like [`modified`](Entry::modified).
    pub accessed: Option<SystemTime>,
    /// Raw symlink target for link entries (`None` for files and
    /// directories): the `SL` target on ISO, the decoded path-component
    /// target on UDF.
    pub link: Option<Vec<u8>>,
}

impl Entry {
    /// True for symbolic links (a target is present), regardless of
    /// the directory flag: links are never descended into.
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.link.is_some()
    }
}

/// A readable filesystem tree: listings plus chunked file reads. The
/// adapters below are thin — they translate listings and resolve
/// paths, and every byte still comes from the reader they wrap.
pub trait Source {
    /// Children of the root directory, in store order (the caller
    /// sorts).
    fn root_entries(&self) -> Result<Vec<Entry>>;

    /// Children of the directory at `dir` (name bytes from the root),
    /// in store order (the caller sorts).
    fn child_entries(&self, dir: &[Vec<u8>]) -> Result<Vec<Entry>>;

    /// Read up to `buf.len()` bytes of the file at `file` (name bytes
    /// from the root) at `offset`: returns the bytes placed, 0 at end
    /// of file. Refuses offsets past the length, naming both.
    fn read_bytes(&self, file: &[Vec<u8>], offset: u64, buf: &mut [u8]) -> Result<usize>;
}

/// Convert a [`RockTime`] stamp (UTC plus `offset_quarters` signed
/// quarters of an hour) to [`SystemTime`]: civil-days arithmetic
/// (Howard Hinnant's days-from-civil), no dependency, total — out
/// means `None`, never a guess.
///
/// Refused rather than placed: months outside 1..12, days outside
/// the month's length (leap years counted), hours past 23,
/// minutes/seconds past 59, centiseconds past 99. A stamp the reader
/// accepted but this cannot place (a leap second, a February 30th)
/// reads as absent in the adapter, not as an error. `i64` carries
/// millennia either way, so no checked arithmetic is needed at these
/// magnitudes — and every result stays far inside [`SystemTime`]'s
/// range, so no conversion here can panic.
fn rock_time_to_system_time(stamp: &RockTime) -> Option<SystemTime> {
    let leap = stamp.year.is_multiple_of(4)
        && (!stamp.year.is_multiple_of(100) || stamp.year.is_multiple_of(400));
    let max_day: u16 = match stamp.month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if stamp.day == 0 || u16::from(stamp.day) > max_day {
        return None;
    }
    if stamp.hour > 23 || stamp.minute > 59 || stamp.second > 59 || stamp.centiseconds > 99 {
        return None;
    }
    let year = i64::from(stamp.year);
    let month = i64::from(stamp.month);
    let day = i64::from(stamp.day);
    let adjusted = if month <= 2 { year - 1 } else { year };
    let era = adjusted.div_euclid(400);
    let yoe = adjusted - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86_400
        + i64::from(stamp.hour) * 3_600
        + i64::from(stamp.minute) * 60
        + i64::from(stamp.second)
        - i64::from(stamp.offset_quarters) * 900;
    let nanos = u32::from(stamp.centiseconds) * 10_000_000;
    if secs >= 0 {
        Some(UNIX_EPOCH + Duration::new(secs as u64, nanos))
    } else {
        Some(UNIX_EPOCH - Duration::new(secs.unsigned_abs(), 0) + Duration::new(0, nanos))
    }
}

/// [`Source`] over an [`IsoReader`]: listings translate
/// [`Entry`](crate::iso::reader::Entry) runs 1:1 (store order kept,
/// `.`/`..` already skipped by the reader), sizes come from the
/// joined `data_len`, and reads stream through `open_file` plus
/// `read_open_at` without ever buffering a whole file.
///
/// Two fidelity boundaries, both inherited from the reader, never
/// invented here: paths render in the reader's `/`-separated form
/// (names that are not valid UTF-8 cannot round-trip through its
/// `&str` lookup — the same lossy boundary its `walk` documents),
/// and Rock Ridge alternate names resolve like the reader resolves
/// them (preferred on a SUSP volume). Symlinks list with their
/// target but are never followed (see [`walk`](super::walk)).
#[derive(Debug)]
pub struct IsoSource {
    reader: IsoReader,
}

impl IsoSource {
    /// Wrap an opened [`IsoReader`].
    pub fn new(reader: IsoReader) -> Self {
        Self { reader }
    }

    /// The reader's `/`-separated path form for `dir` (empty means
    /// the root).
    fn path_str(dir: &[Vec<u8>]) -> String {
        let mut path = String::new();
        for component in dir {
            path.push('/');
            path.push_str(&String::from_utf8_lossy(component));
        }
        if path.is_empty() {
            path.push('/');
        }
        path
    }

    /// Translate one reader listing, carrying symlink entries as links
    /// (never followed) alongside files and directories. Modes ride
    /// whole (the destination masks); stamps convert to UTC, and a
    /// stamp the converter cannot place reads as absent. Symlinks size
    /// 0: a recreated link costs no bytes, and a dereferenced link's
    /// size is resolved during the walk, not here.
    fn translate(&self, entries: Vec<crate::iso::reader::Entry>) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        for entry in &entries {
            let link = entry.symlink_target.clone().map(String::into_bytes);
            let is_symlink = link.is_some();
            out.push(Entry {
                name: entry.file_name(),
                is_dir: entry.is_dir && !is_symlink,
                size: if is_symlink || entry.is_dir {
                    0
                } else {
                    u64::from(entry.data_len)
                },
                mode: entry.posix.as_ref().map(|posix| posix.mode),
                modified: entry
                    .times
                    .as_ref()
                    .and_then(|times| times.modification.as_ref())
                    .and_then(rock_time_to_system_time),
                accessed: entry
                    .times
                    .as_ref()
                    .and_then(|times| times.access.as_ref())
                    .and_then(rock_time_to_system_time),
                link,
            });
        }
        Ok(out)
    }
}

impl Source for IsoSource {
    fn root_entries(&self) -> Result<Vec<Entry>> {
        self.translate(self.reader.read_dir("/")?)
    }

    fn child_entries(&self, dir: &[Vec<u8>]) -> Result<Vec<Entry>> {
        self.translate(self.reader.read_dir(&Self::path_str(dir))?)
    }

    fn read_bytes(&self, file: &[Vec<u8>], offset: u64, buf: &mut [u8]) -> Result<usize> {
        let path = Self::path_str(file);
        let handle = self.reader.open_file(&path)?;
        self.reader
            .read_open_at(&handle, offset, buf)
            .map_err(|error| {
                CoreError::invalid(format!("cannot read `{path}` at offset {offset}: {error}"))
            })
    }
}

/// [`Source`] over a [`UdfReader`]: paths resolve by descending from
/// the root matching exact name bytes (UDF names are decoded strings,
/// so the round trip is exact), sizes come from the opened file's
/// information length, and reads stream through `open_file` plus
/// `read_open_at` without ever buffering a whole file.
///
/// Entries the reader cannot open as data (FIFOs and the rest —
/// each refuses with its kind named) fail the listing that contains
/// them: failing fast before any byte moves. Symlinks list with their
/// target instead (see [`walk`](super::walk)).
#[derive(Debug)]
pub struct UdfSource {
    reader: UdfReader,
}

impl UdfSource {
    /// Wrap an opened [`UdfReader`].
    pub fn new(reader: UdfReader) -> Self {
        Self { reader }
    }

    /// Resolve `dir` (name bytes from the root) to its reader entry by
    /// descending from the root; an empty path is the root itself.
    fn resolve(&self, dir: &[Vec<u8>]) -> Result<crate::udf::reader::Entry> {
        let mut current = self.reader.root();
        for component in dir {
            let children = self.reader.read_dir(&current)?;
            let next = children
                .iter()
                .find(|child| child.name.as_bytes() == component.as_slice())
                .ok_or_else(|| {
                    CoreError::invalid(format!(
                        "copy cannot resolve '{}': no such entry",
                        String::from_utf8_lossy(component)
                    ))
                })?;
            current = next.clone();
        }
        Ok(current)
    }

    /// Translate one reader listing, carrying symlink entries as links
    /// alongside files and directories. Regular files size through
    /// `open_file` (which is also what refuses FIFOs and special files
    /// with their kind named); symlinks and directories size 0 (a link
    /// costs no bytes — a dereferenced link's size resolves during the
    /// walk). Modes and stamps ride from the listing itself.
    fn translate(&self, entries: Vec<crate::udf::reader::Entry>) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        for entry in &entries {
            let link = entry.symlink_target.clone().map(String::into_bytes);
            let is_symlink = link.is_some();
            let size = if is_symlink || entry.is_directory {
                0
            } else {
                self.reader.open_file(entry)?.len()
            };
            out.push(Entry {
                name: entry.name.clone().into_bytes(),
                is_dir: entry.is_directory && !is_symlink,
                size,
                mode: entry.mode,
                modified: entry.modified,
                accessed: entry.accessed,
                link,
            });
        }
        Ok(out)
    }
}

impl Source for UdfSource {
    fn root_entries(&self) -> Result<Vec<Entry>> {
        let root = self.reader.root();
        self.translate(self.reader.read_dir(&root)?)
    }

    fn child_entries(&self, dir: &[Vec<u8>]) -> Result<Vec<Entry>> {
        let resolved = self.resolve(dir)?;
        self.translate(self.reader.read_dir(&resolved)?)
    }

    fn read_bytes(&self, file: &[Vec<u8>], offset: u64, buf: &mut [u8]) -> Result<usize> {
        let resolved = self.resolve(file)?;
        let handle = self.reader.open_file(&resolved)?;
        self.reader.read_open_at(&handle, offset, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::fs::Volume;
    use crate::iso::FLAG_DIRECTORY;
    use crate::iso::SECTOR_BYTES;
    use crate::iso::descriptor::TYPE_BOOT;
    use crate::iso::descriptor::TYPE_PRIMARY;
    use crate::iso::descriptor::TYPE_TERMINATOR;
    use crate::iso::record::RECORD_FIXED_LEN;
    use std::os::unix::fs::PermissionsExt;

    const ROOT_SECTOR: u32 = 20;
    const DIR_A_SECTOR: u32 = 21;
    const DIR_B_SECTOR: u32 = 22;
    const FILE_TOP_SECTOR: u32 = 23;
    const FILE_NESTED_SECTOR: u32 = 24;
    const IMAGE_SECTORS: u32 = 32;

    /// Encode one directory record, mirroring the on-disk layout the
    /// parser reads (both-endian words, zero date, sequence 1, the
    /// even-length pad, no system-use tail). Copied from the
    /// `iso/reader.rs` test builders, not refactored: those helpers
    /// are private to their module on purpose.
    fn encode_record(extent: u32, data_len: u32, flags: u8, identifier: &[u8]) -> Vec<u8> {
        let pad = if identifier.len().is_multiple_of(2) {
            1
        } else {
            0
        };
        let len = RECORD_FIXED_LEN + identifier.len() + pad;
        let mut out = vec![0u8; len];
        out[0] = len as u8;
        out[2..6].copy_from_slice(&extent.to_le_bytes());
        out[6..10].copy_from_slice(&extent.to_be_bytes());
        out[10..14].copy_from_slice(&data_len.to_le_bytes());
        out[14..18].copy_from_slice(&data_len.to_be_bytes());
        out[25] = flags;
        out[28..30].copy_from_slice(&1u16.to_le_bytes());
        out[30..32].copy_from_slice(&1u16.to_be_bytes());
        out[32] = identifier.len() as u8;
        out[33..33 + identifier.len()].copy_from_slice(identifier);
        out
    }

    /// Pack records back to back at the start of one zeroed sector.
    /// Copied from the `iso/reader.rs` test builders (see
    /// [`encode_record`]).
    fn dir_sector(records: &[Vec<u8>]) -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        let mut offset = 0;
        for record in records {
            sector[offset..offset + record.len()].copy_from_slice(record);
            offset += record.len();
        }
        sector
    }

    /// Primary-descriptor sector with `label` and the root at
    /// (`root_extent`, `root_len`). Copied from the `iso/reader.rs`
    /// test builders (see [`encode_record`]).
    fn primary_sector(label: &str, root_extent: u32, root_len: u32) -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = TYPE_PRIMARY;
        sector[1..6].copy_from_slice(b"CD001");
        sector[6] = 1;
        let label_bytes = label.as_bytes();
        let take = label_bytes.len().min(32);
        sector[40..40 + take].copy_from_slice(&label_bytes[..take]);
        for byte in sector.iter_mut().skip(40 + take).take(32 - take) {
            *byte = b' ';
        }
        sector[80..84].copy_from_slice(&IMAGE_SECTORS.to_le_bytes());
        sector[84..88].copy_from_slice(&IMAGE_SECTORS.to_be_bytes());
        sector[128..130].copy_from_slice(&2048u16.to_le_bytes());
        sector[130..132].copy_from_slice(&2048u16.to_be_bytes());
        let root = encode_record(root_extent, root_len, FLAG_DIRECTORY, b"\x00");
        sector[156..156 + root.len()].copy_from_slice(&root);
        sector
    }

    /// Boot-record sector. Copied from the `iso/reader.rs` test
    /// builders (see [`encode_record`]).
    fn boot_sector() -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = TYPE_BOOT;
        sector[1..6].copy_from_slice(b"CD001");
        sector[6] = 1;
        sector
    }

    /// Terminator sector. Copied from the `iso/reader.rs` test builders
    /// (see [`encode_record`]).
    fn terminator_sector() -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = TYPE_TERMINATOR;
        sector[1..6].copy_from_slice(b"CD001");
        sector[6] = 1;
        sector
    }

    /// Whole primary-only fixture image: descriptors at 16..18, root
    /// at 20 holding `B/`, `TOP.TXT;1` and `A/` in that (unsorted)
    /// on-disk order, `A/` at 21 holding `NESTED.TXT;1`, `B/` at 22
    /// empty, file contents after. Synthetic layout only, claims
    /// nothing about real mastering tools.
    fn fixture_bytes() -> Vec<u8> {
        let mut image = vec![0u8; IMAGE_SECTORS as usize * SECTOR_BYTES];
        let put = |image: &mut Vec<u8>, sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(
            &mut image,
            16,
            &primary_sector("LABEL", ROOT_SECTOR, SECTOR_BYTES as u32),
        );
        put(&mut image, 17, &boot_sector());
        put(&mut image, 18, &terminator_sector());
        put(
            &mut image,
            ROOT_SECTOR,
            &dir_sector(&[
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(DIR_B_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"B"),
                encode_record(FILE_TOP_SECTOR, 7, 0, b"TOP.TXT;1"),
                encode_record(DIR_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"A"),
            ]),
        );
        put(
            &mut image,
            DIR_A_SECTOR,
            &dir_sector(&[
                encode_record(DIR_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(DIR_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(FILE_NESTED_SECTOR, 6, 0, b"NESTED.TXT;1"),
            ]),
        );
        put(
            &mut image,
            DIR_B_SECTOR,
            &dir_sector(&[
                encode_record(DIR_B_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(DIR_B_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            ]),
        );
        put(&mut image, FILE_TOP_SECTOR, b"top-txt");
        put(&mut image, FILE_NESTED_SECTOR, b"nested");
        image
    }

    /// Fixture image opened as an [`IsoSource`].
    fn fixture_source() -> IsoSource {
        let bytes = fixture_bytes();
        let total = bytes.len() as u64;
        let mut volume = VecVolume::new(total, 512).expect("the fixture fits in RAM");
        volume.write_all_at(0, &bytes).expect("the fixture writes");
        IsoSource::new(IsoReader::open(Box::new(volume)).expect("the fixture opens"))
    }

    /// Encode one directory record with a raw system-use tail (the
    /// `len` byte covers the tail): same fixed fields as
    /// [`encode_record`], then `system_use` after the even-length
    /// pad. Copied pattern (see [`encode_record`]).
    fn encode_record_su(
        extent: u32,
        data_len: u32,
        flags: u8,
        identifier: &[u8],
        system_use: &[u8],
    ) -> Vec<u8> {
        let pad = if identifier.len().is_multiple_of(2) {
            1
        } else {
            0
        };
        let len = RECORD_FIXED_LEN + identifier.len() + pad + system_use.len();
        let mut out = vec![0u8; len];
        out[0] = len as u8;
        out[2..6].copy_from_slice(&extent.to_le_bytes());
        out[6..10].copy_from_slice(&extent.to_be_bytes());
        out[10..14].copy_from_slice(&data_len.to_le_bytes());
        out[14..18].copy_from_slice(&data_len.to_be_bytes());
        out[25] = flags;
        out[28..30].copy_from_slice(&1u16.to_le_bytes());
        out[30..32].copy_from_slice(&1u16.to_be_bytes());
        out[32] = identifier.len() as u8;
        out[33..33 + identifier.len()].copy_from_slice(identifier);
        let tail_at = RECORD_FIXED_LEN + identifier.len() + pad;
        out[tail_at..tail_at + system_use.len()].copy_from_slice(system_use);
        out
    }

    /// SUSP `SP` marker (7 bytes, skip 0): the root `.` record carries
    /// this so the reader parses Rock Ridge on the volume.
    fn sp_marker() -> Vec<u8> {
        vec![b'S', b'P', 7, 1, 0xBE, 0xEF, 0]
    }

    /// A 36-byte `PX` entry (no serial, like `xorriso` writes): full
    /// `mode` with file type bits, one link, root ownership, both
    /// endian words.
    fn px_entry(mode: u32) -> Vec<u8> {
        let mut entry = vec![0u8; 36];
        entry[0..2].copy_from_slice(b"PX");
        entry[2] = 36;
        entry[3] = 1;
        entry[4..8].copy_from_slice(&mode.to_le_bytes());
        entry[8..12].copy_from_slice(&mode.to_be_bytes());
        entry[12..16].copy_from_slice(&1u32.to_le_bytes());
        entry[16..20].copy_from_slice(&1u32.to_be_bytes());
        entry
    }

    /// A 12-byte `TF` entry carrying one 7-byte modification stamp.
    fn tf_entry(
        year_from_1900: u8,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Vec<u8> {
        let mut entry = vec![0u8; 12];
        entry[0..2].copy_from_slice(b"TF");
        entry[2] = 12;
        entry[3] = 1;
        entry[4] = 0x02;
        entry[5..12].copy_from_slice(&[year_from_1900, month, day, hour, minute, second, 0]);
        entry
    }

    /// SUSP fixture image: root at 20 holding `A/` (`0o40755`) and
    /// `F.TXT;1` (`0o100644`), `A/` at 21 holding `N.TXT;1`
    /// (`0o100644`), `B/` at 24 (`0o40500`) holding `M.TXT;1`
    /// (`0o100644`) — every entry with a `TF` modification stamp for
    /// 2024-02-29T12:34:56Z. Synthetic layout only, claims nothing
    /// about real mastering tools.
    fn metadata_fixture_bytes() -> Vec<u8> {
        const DIR_B_SECTOR: u32 = 24;
        const FILE_M_SECTOR: u32 = 25;
        const FILE_F_SECTOR: u32 = 26;
        const FILE_N_SECTOR: u32 = 27;
        const MODE_DIR: u32 = 0o40755;
        const MODE_NARROW_DIR: u32 = 0o40500;
        const MODE_FILE: u32 = 0o100644;
        let stamp = || tf_entry(124, 2, 29, 12, 34, 56);
        let px_tf = |mode: u32| {
            let mut su = px_entry(mode);
            su.extend_from_slice(&stamp());
            su
        };
        let mut image = vec![0u8; IMAGE_SECTORS as usize * SECTOR_BYTES];
        let put = |image: &mut Vec<u8>, sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(
            &mut image,
            16,
            &primary_sector("LABEL", ROOT_SECTOR, SECTOR_BYTES as u32),
        );
        put(&mut image, 17, &boot_sector());
        put(&mut image, 18, &terminator_sector());
        let dot = encode_record_su(
            ROOT_SECTOR,
            SECTOR_BYTES as u32,
            FLAG_DIRECTORY,
            b"\x00",
            &sp_marker(),
        );
        let parent = encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01");
        put(
            &mut image,
            ROOT_SECTOR,
            &dir_sector(&[
                dot,
                parent,
                encode_record_su(
                    DIR_A_SECTOR,
                    SECTOR_BYTES as u32,
                    FLAG_DIRECTORY,
                    b"A",
                    &px_tf(MODE_DIR),
                ),
                encode_record_su(
                    DIR_B_SECTOR,
                    SECTOR_BYTES as u32,
                    FLAG_DIRECTORY,
                    b"B",
                    &px_tf(MODE_NARROW_DIR),
                ),
                encode_record_su(FILE_F_SECTOR, 2, 0, b"F.TXT;1", &px_tf(MODE_FILE)),
            ]),
        );
        put(
            &mut image,
            DIR_A_SECTOR,
            &dir_sector(&[
                encode_record(DIR_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(DIR_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record_su(FILE_N_SECTOR, 2, 0, b"N.TXT;1", &px_tf(MODE_FILE)),
            ]),
        );
        put(
            &mut image,
            DIR_B_SECTOR,
            &dir_sector(&[
                encode_record(DIR_B_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(DIR_B_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record_su(FILE_M_SECTOR, 2, 0, b"M.TXT;1", &px_tf(MODE_FILE)),
            ]),
        );
        put(&mut image, FILE_F_SECTOR, b"f!");
        put(&mut image, FILE_N_SECTOR, b"n!");
        put(&mut image, FILE_M_SECTOR, b"m!");
        image
    }

    /// Metadata fixture opened as an [`IsoSource`].
    fn metadata_source() -> IsoSource {
        let bytes = metadata_fixture_bytes();
        let total = bytes.len() as u64;
        let mut volume = VecVolume::new(total, 512).expect("the fixture fits in RAM");
        volume.write_all_at(0, &bytes).expect("the fixture writes");
        IsoSource::new(IsoReader::open(Box::new(volume)).expect("the fixture opens"))
    }

    /// A recording no-op [`Progress`](super::super::Progress) that
    /// keeps warning lines: metadata-quiet runs must warn nothing.
    struct WarnLog {
        warns: Vec<String>,
    }

    impl super::super::Progress for WarnLog {
        fn report(&mut self, _done_bytes: u64, _total_bytes: u64) {}

        fn warn(&mut self, text: &str) {
            self.warns.push(text.to_string());
        }
    }

    #[test]
    fn copies_modes_and_mtimes_from_px_tf() {
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;
        use std::time::Duration;
        use std::time::UNIX_EPOCH;

        // Every entry carries PX + TF: after the walk, file modes are
        // 0o644, A/ is 0o755, narrow B/ is 0o500 (its child still
        // copied — the mode landed after the children), and every
        // mtime is the stamped instant (`date -u` says
        // 2024-02-29T12:34:56Z is 1709210096).
        let source = metadata_source();
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let summary = super::super::walk(
            &source,
            scratch.path(),
            &super::super::CopyOptions {
                free_bytes: None,
                replacer: None,
            },
            &mut WarnLog { warns: Vec::new() },
        )
        .expect("the metadata tree copies");
        assert_eq!(
            summary,
            super::super::Summary {
                directories: 2,
                files: 3,
                bytes: 6,
                renamed: 0,
            }
        );
        let mode = |path: &Path| {
            std::fs::metadata(path)
                .expect("entry stats")
                .permissions()
                .mode()
                & 0o777
        };
        let mtime = |path: &Path| {
            std::fs::metadata(path)
                .expect("entry stats")
                .modified()
                .expect("mtime reads")
        };
        let expected = UNIX_EPOCH + Duration::new(1_709_210_096, 0);
        for (name, contents) in [
            ("F.TXT", b"f!".as_slice()),
            ("A/N.TXT", b"n!".as_slice()),
            ("B/M.TXT", b"m!".as_slice()),
        ] {
            let path = scratch.path().join(name);
            assert_eq!(std::fs::read(&path).expect("file reads back"), contents);
            assert_eq!(mode(&path), 0o644, "{name} carries its PX mode");
            assert_eq!(mtime(&path), expected, "{name} carries its TF stamp");
        }
        for (name, mode_bits) in [("A", 0o755), ("B", 0o500)] {
            let path = scratch.path().join(name);
            assert_eq!(mode(&path), mode_bits, "{name}/ carries its PX mode");
            assert_eq!(mtime(&path), expected, "{name}/ carries its TF stamp");
        }
    }

    #[test]
    fn entries_without_metadata_copy_with_defaults_and_no_warnings() {
        // The plain fixture carries no PX/TF: the copy succeeds, warns
        // nothing, and modes match a control file created the same
        // way (whatever the ambient umask).
        let source = fixture_source();
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let control = scratch.path().join("control");
        std::fs::write(&control, b"").expect("the control writes");
        let control_mode = std::fs::metadata(&control)
            .expect("control stats")
            .permissions()
            .mode();
        let mut progress = WarnLog { warns: Vec::new() };
        super::super::walk(
            &source,
            scratch.path(),
            &super::super::CopyOptions {
                free_bytes: None,
                replacer: None,
            },
            &mut progress,
        )
        .expect("a metadata-free tree copies");
        // The control file itself is untouched by the walk (not part
        // of the source tree): remove it before asserting contents.
        std::fs::remove_file(&control).expect("the control removes");
        let top_mode = std::fs::metadata(scratch.path().join("TOP.TXT"))
            .expect("top stats")
            .permissions()
            .mode();
        assert_eq!(top_mode, control_mode, "no PX means the default mode");
        assert!(
            progress.warns.is_empty(),
            "no metadata means no warnings: {:?}",
            progress.warns
        );
    }

    /// A no-op [`Progress`](super::super::Progress) for the walk test
    /// below (ordering and contents are the assertions, not the meter).
    struct Sink;

    impl super::super::Progress for Sink {
        fn report(&mut self, _done_bytes: u64, _total_bytes: u64) {}
    }

    #[test]
    fn copies_an_iso_tree_byte_for_byte() {
        // The fixture tree (two directories, one nested file) lands
        // byte-for-byte in a scratch directory with exact summary
        // counts: A/ and B/ created, TOP.TXT and NESTED.TXT written.
        let source = fixture_source();
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let summary = super::super::walk(
            &source,
            scratch.path(),
            &super::super::CopyOptions {
                free_bytes: None,
                replacer: None,
            },
            &mut Sink,
        )
        .expect("the iso tree copies");
        assert_eq!(
            summary,
            super::super::Summary {
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
    }

    /// Second fixture image: root at 20 holding `DOC.;12` and
    /// `SUB.;2` (multi-digit versions the reader does NOT strip — only
    /// exact `;1` strips there — so the walk's own rules fire), `SUB.;2`
    /// at 25 holding `F.TXT;1`, contents after. Synthetic layout only,
    /// claims nothing about real mastering tools.
    fn version_dot_fixture_bytes() -> Vec<u8> {
        const SUB_SECTOR: u32 = 25;
        const FILE_DOC_SECTOR: u32 = 26;
        const FILE_F_SECTOR: u32 = 27;
        let mut image = vec![0u8; IMAGE_SECTORS as usize * SECTOR_BYTES];
        let put = |image: &mut Vec<u8>, sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(
            &mut image,
            16,
            &primary_sector("LABEL", ROOT_SECTOR, SECTOR_BYTES as u32),
        );
        put(&mut image, 17, &boot_sector());
        put(&mut image, 18, &terminator_sector());
        put(
            &mut image,
            ROOT_SECTOR,
            &dir_sector(&[
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(FILE_DOC_SECTOR, 3, 0, b"DOC.;12"),
                encode_record(SUB_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"SUB.;2"),
            ]),
        );
        put(
            &mut image,
            SUB_SECTOR,
            &dir_sector(&[
                encode_record(SUB_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(SUB_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(FILE_F_SECTOR, 5, 0, b"F.TXT;1"),
            ]),
        );
        put(&mut image, FILE_DOC_SECTOR, b"doc");
        put(&mut image, FILE_F_SECTOR, b"data!");
        image
    }

    #[test]
    fn copies_versioned_and_dotted_iso_names_sanitised() {
        // End to end through the reader: `DOC.;12` stores as `DOC`
        // (version stripped past the reader's exact-`;1` rule, then
        // the trailing dot trimmed) and `SUB.;2/` as `SUB`, with
        // contents intact and both entries counted as renamed.
        // `F.TXT;1` arrives pre-stripped by the reader, so the walk
        // stores it unchanged.
        let bytes = version_dot_fixture_bytes();
        let total = bytes.len() as u64;
        let mut volume = VecVolume::new(total, 512).expect("the fixture fits in RAM");
        volume.write_all_at(0, &bytes).expect("the fixture writes");
        let source = IsoSource::new(IsoReader::open(Box::new(volume)).expect("the fixture opens"));
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let summary = super::super::walk(
            &source,
            scratch.path(),
            &super::super::CopyOptions {
                free_bytes: None,
                replacer: None,
            },
            &mut Sink,
        )
        .expect("the dotted tree copies");
        assert_eq!(
            summary,
            super::super::Summary {
                directories: 1,
                files: 2,
                bytes: 8,
                renamed: 2,
            }
        );
        assert_eq!(
            std::fs::read(scratch.path().join("DOC")).expect("stripped reads back"),
            b"doc"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("SUB").join("F.TXT")).expect("nested reads back"),
            b"data!"
        );
    }

    #[test]
    fn iso_adapter_lists_in_store_order_and_reads_in_chunks() {
        // Root children arrive in on-disk order (B, TOP.TXT, A) —
        // sorting is the walk's job, pinned there. Directory entries
        // size 0, files carry their data length.
        let source = fixture_source();
        let root = source.root_entries().expect("the root lists");
        assert_eq!(
            root.iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>(),
            [b"B".to_vec(), b"TOP.TXT".to_vec(), b"A".to_vec()]
        );
        assert!(root[0].is_dir && root[0].size == 0);
        assert!(!root[1].is_dir && root[1].size == 7);
        // Children resolve under their directory.
        let children = source.child_entries(&[b"A".to_vec()]).expect("A/ lists");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name, b"NESTED.TXT".to_vec());
        assert_eq!(children[0].size, 6);
        // Reads stream in caller-sized chunks with 0 past the end.
        let mut first = [0u8; 4];
        let placed = source
            .read_bytes(&[b"TOP.TXT".to_vec()], 0, &mut first)
            .expect("the head reads");
        assert_eq!(placed, 4);
        assert_eq!(&first, b"top-");
        let mut rest = [0u8; 4];
        let placed = source
            .read_bytes(&[b"TOP.TXT".to_vec()], 4, &mut rest)
            .expect("the tail reads");
        assert_eq!(placed, 3);
        assert_eq!(&rest[..3], b"txt");
        let mut past = [0u8; 4];
        assert_eq!(
            source
                .read_bytes(&[b"TOP.TXT".to_vec()], 7, &mut past)
                .expect("the end reads"),
            0
        );
        // Offsets past the length refuse naming both numbers.
        let mut buf = [0u8; 1];
        let error = source
            .read_bytes(&[b"TOP.TXT".to_vec()], 8, &mut buf)
            .expect_err("a past-the-end read refuses");
        assert!(error.to_string().contains('8'), "{error:?}");
        assert!(error.to_string().contains('7'), "{error:?}");
    }

    /// One SUSP entry with the computed length byte and version 1.
    /// Copied from the `iso/reader.rs` test builders, not refactored:
    /// those helpers are private to their module on purpose.
    fn susp_entry(sig: &[u8; 2], payload: &[u8]) -> Vec<u8> {
        let mut out = vec![sig[0], sig[1], (4 + payload.len()) as u8, 1];
        out.extend_from_slice(payload);
        out
    }

    /// An `SL` entry over `(component flags, text)` pairs (flag 0 is
    /// a plain component, `0x04` climbs to the parent). Copied from
    /// the `iso/reader.rs` test builders (see [`susp_entry`]).
    fn sl_entry(comps: &[(u8, &[u8])]) -> Vec<u8> {
        let mut payload = vec![0];
        for (flags, text) in comps {
            payload.push(*flags);
            payload.push(text.len() as u8);
            payload.extend_from_slice(text);
        }
        susp_entry(b"SL", &payload)
    }

    /// Symlink fixture image: root at 20 holding `FILE.TXT;1` (9
    /// bytes), `LINK;1` (an `SL` link to `FILE.TXT`) and `SUB/` at 25
    /// holding `UP;1` (an `SL` link to `../FILE.TXT`). The root dot
    /// record carries `SP` so the reader parses Rock Ridge.
    /// Synthetic layout only, claims nothing about real mastering
    /// tools.
    fn symlink_fixture_bytes() -> Vec<u8> {
        const SUB_SECTOR: u32 = 25;
        const FILE_SECTOR: u32 = 26;
        let mut image = vec![0u8; IMAGE_SECTORS as usize * SECTOR_BYTES];
        let put = |image: &mut Vec<u8>, sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(
            &mut image,
            16,
            &primary_sector("LABEL", ROOT_SECTOR, SECTOR_BYTES as u32),
        );
        put(&mut image, 17, &boot_sector());
        put(&mut image, 18, &terminator_sector());
        let dot = encode_record_su(
            ROOT_SECTOR,
            SECTOR_BYTES as u32,
            FLAG_DIRECTORY,
            b"\x00",
            &sp_marker(),
        );
        let parent = encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01");
        put(
            &mut image,
            ROOT_SECTOR,
            &dir_sector(&[
                dot,
                parent,
                encode_record(FILE_SECTOR, 9, 0, b"FILE.TXT;1"),
                encode_record_su(0, 0, 0, b"LINK;1", &sl_entry(&[(0, b"FILE.TXT")])),
                encode_record(SUB_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"SUB"),
            ]),
        );
        put(
            &mut image,
            SUB_SECTOR,
            &dir_sector(&[
                encode_record(SUB_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(SUB_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record_su(
                    0,
                    0,
                    0,
                    b"UP;1",
                    &sl_entry(&[(0x04, b""), (0, b"FILE.TXT")]),
                ),
            ]),
        );
        put(&mut image, FILE_SECTOR, b"iso-bytes");
        image
    }

    #[test]
    fn copies_rock_ridge_symlinks_end_to_end() {
        // LINK recreates as a link to FILE.TXT and SUB/UP as a link
        // to ../FILE.TXT; the file lands with its bytes and only its
        // bytes count (one directory, three files, nine bytes), with
        // no warnings.
        let bytes = symlink_fixture_bytes();
        let total = bytes.len() as u64;
        let mut volume = VecVolume::new(total, 512).expect("the fixture fits in RAM");
        volume.write_all_at(0, &bytes).expect("the fixture writes");
        let source = IsoSource::new(IsoReader::open(Box::new(volume)).expect("the fixture opens"));
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = WarnLog { warns: Vec::new() };
        let summary = super::super::walk(
            &source,
            scratch.path(),
            &super::super::CopyOptions {
                free_bytes: None,
                replacer: None,
            },
            &mut progress,
        )
        .expect("the symlink tree copies");
        assert_eq!(
            summary,
            super::super::Summary {
                directories: 1,
                files: 3,
                bytes: 9,
                renamed: 0,
            }
        );
        assert!(
            progress.warns.is_empty(),
            "inside links warn nothing: {:?}",
            progress.warns
        );
        assert_eq!(
            std::fs::read(scratch.path().join("FILE.TXT")).expect("the file reads back"),
            b"iso-bytes"
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
            std::fs::read_link(&link).expect("the LINK target reads"),
            std::path::Path::new("FILE.TXT")
        );
        let up = scratch.path().join("SUB").join("UP");
        assert!(
            std::fs::symlink_metadata(&up)
                .expect("the nested link stats")
                .file_type()
                .is_symlink(),
            "SUB/UP lands as a link"
        );
        assert_eq!(
            std::fs::read_link(&up).expect("the UP target reads"),
            std::path::Path::new("../FILE.TXT")
        );
    }
    /// One [`RockTime`] from parts: the conversion tests below build
    /// stamps directly (the TF decoder is the reader's tested
    /// business, not this slice's).
    fn stamp(year: u16, mdhms: [u8; 5], centiseconds: u8, offset_quarters: i8) -> RockTime {
        RockTime {
            year,
            month: mdhms[0],
            day: mdhms[1],
            hour: mdhms[2],
            minute: mdhms[3],
            second: mdhms[4],
            centiseconds,
            offset_quarters,
        }
    }

    #[test]
    fn rock_time_conversion_places_known_instants() {
        use std::time::Duration;
        use std::time::UNIX_EPOCH;

        // The epoch itself.
        assert_eq!(
            rock_time_to_system_time(&stamp(1970, [1, 1, 0, 0, 0], 0, 0)),
            Some(UNIX_EPOCH)
        );
        // A leap day at noon-plus-change (`date -u` says
        // 2024-02-29T12:34:56Z is 1709210096).
        assert_eq!(
            rock_time_to_system_time(&stamp(2024, [2, 29, 12, 34, 56], 0, 0)),
            Some(UNIX_EPOCH + Duration::new(1_709_210_096, 0))
        );
        // A pre-epoch date lands before the epoch (`1969-12-31 is
        // -86400).
        assert_eq!(
            rock_time_to_system_time(&stamp(1969, [12, 31, 0, 0, 0], 0, 0)),
            Some(UNIX_EPOCH - Duration::new(86_400, 0))
        );
        // An offset-bearing record converts to UTC (`2024-06-01
        // 12:00 at +8 quarters is 10:00Z, 1717236000).
        assert_eq!(
            rock_time_to_system_time(&stamp(2024, [6, 1, 12, 0, 0], 0, 8)),
            Some(UNIX_EPOCH + Duration::new(1_717_236_000, 0))
        );
        // Centiseconds ride along as nanos (`2000-01-01 plus a
        // quarter second is 946684800.25).
        assert_eq!(
            rock_time_to_system_time(&stamp(2000, [1, 1, 0, 0, 0], 25, 0)),
            Some(UNIX_EPOCH + Duration::new(946_684_800, 250_000_000))
        );
        // A leap century places (`2000-02-29T00:00:00Z` is 951782400
        // per `date -u`: divisible by 400, so February holds 29 days).
        assert_eq!(
            rock_time_to_system_time(&stamp(2000, [2, 29, 0, 0, 0], 0, 0)),
            Some(UNIX_EPOCH + Duration::new(951_782_400, 0))
        );
    }

    #[test]
    fn rock_time_conversion_refuses_impossible_dates() {
        // Each field outside its range refuses rather than placing a
        // guess — and February 29th honours the full leap rule
        // (1900 and 2100 refuse, 2000 and 2024 place), not just the
        // 31-day ceiling.
        for bad in [
            stamp(2024, [0, 15, 0, 0, 0], 0, 0),
            stamp(2024, [13, 15, 0, 0, 0], 0, 0),
            stamp(2024, [2, 0, 0, 0, 0], 0, 0),
            stamp(2024, [2, 32, 0, 0, 0], 0, 0),
            stamp(2023, [2, 29, 0, 0, 0], 0, 0),
            stamp(2023, [2, 30, 0, 0, 0], 0, 0),
            stamp(1900, [2, 29, 0, 0, 0], 0, 0),
            stamp(2100, [2, 29, 0, 0, 0], 0, 0),
            stamp(2024, [4, 31, 0, 0, 0], 0, 0),
            stamp(2024, [1, 1, 24, 0, 0], 0, 0),
            stamp(2024, [1, 1, 0, 60, 0], 0, 0),
            stamp(2024, [1, 1, 0, 0, 60], 0, 0),
            stamp(2024, [1, 1, 0, 0, 0], 100, 0),
        ] {
            assert_eq!(rock_time_to_system_time(&bad), None, "{bad:?}");
        }
        // ...while a leap February 29th places
        // (`2024-02-29T00:00:00Z` is 1709164800).
        assert_eq!(
            rock_time_to_system_time(&stamp(2024, [2, 29, 0, 0, 0], 0, 0)),
            Some(std::time::UNIX_EPOCH + std::time::Duration::new(1_709_164_800, 0))
        );
    }

    /// Block size the synthetic UDF volume below uses.
    const UF_SIZE: u32 = 512;
    /// Absolute block of the anchor (sector 256 in 512-byte units).
    const UF_ANCHOR_AT: u32 = 256;
    /// Partition start the synthetic volume uses.
    const UF_PART_AT: u32 = 257;

    /// Recognition region: BEA01, NSR03, TEA01. Copied from the
    /// `udf/reader.rs` test builders, not refactored: those helpers
    /// are private to their module on purpose.
    fn uf_recognition() -> Vec<u8> {
        let mut region = vec![0u8; 6144];
        for (index, id) in [*b"BEA01", *b"NSR03", *b"TEA01"].iter().enumerate() {
            let base = index * 2048;
            region[base] = 0x00;
            region[base + 1..base + 6].copy_from_slice(id);
            region[base + 6] = 0x01;
        }
        region
    }

    /// Anchor block with a main extent (8 blocks from 96) and no
    /// reserve, CRC fixed. Copied (see [`uf_recognition`]).
    fn uf_anchor() -> Vec<u8> {
        let mut block = vec![0u8; UF_SIZE as usize];
        block[16..20].copy_from_slice(&(8 * UF_SIZE).to_le_bytes());
        block[20..24].copy_from_slice(&96u32.to_le_bytes());
        crate::udf::stamp_tag(&mut block, 2, (UF_SIZE - 16) as u16, UF_ANCHOR_AT);
        block
    }

    /// Zeroed block with only a tag: primary (1), unallocated (7),
    /// implementation use (4) and terminator (8) carry nothing the
    /// adapter test reads. Copied (see [`uf_recognition`]).
    fn uf_skipped(lbn: u32, id: u16) -> Vec<u8> {
        let mut block = vec![0u8; UF_SIZE as usize];
        crate::udf::stamp_tag(&mut block, id, (UF_SIZE - 16) as u16, lbn);
        block
    }

    /// Partition body for number 0 at `UF_PART_AT`, contents `+NSR03`.
    /// Copied (see [`uf_recognition`]).
    fn uf_partition(lbn: u32) -> Vec<u8> {
        let mut block = vec![0u8; UF_SIZE as usize];
        block[22..24].copy_from_slice(&0u16.to_le_bytes());
        block[25..31].copy_from_slice(b"+NSR03");
        block[188..192].copy_from_slice(&UF_PART_AT.to_le_bytes());
        block[192..196].copy_from_slice(&900u32.to_le_bytes());
        crate::udf::stamp_tag(&mut block, 5, (UF_SIZE - 16) as u16, lbn);
        block
    }

    /// Logical volume body: label `LABEL`, revision 2.01, one type-1
    /// map to partition 0, file set at partition-relative block 8.
    /// Copied (see [`uf_recognition`]).
    fn uf_logical(lbn: u32) -> Vec<u8> {
        let mut block = vec![0u8; UF_SIZE as usize];
        block[84] = 8;
        block[85..90].copy_from_slice(b"LABEL");
        block[84 + 127] = 6;
        block[212..216].copy_from_slice(&UF_SIZE.to_le_bytes());
        block[217..236].copy_from_slice(b"*OSTA UDF Compliant");
        block[240..242].copy_from_slice(&0x0201u16.to_le_bytes());
        block[248..252].copy_from_slice(&UF_SIZE.to_le_bytes());
        block[252..256].copy_from_slice(&8u32.to_le_bytes());
        block[264..268].copy_from_slice(&6u32.to_le_bytes());
        block[268..272].copy_from_slice(&1u32.to_le_bytes());
        block[440..446].copy_from_slice(&[1, 6, 1, 0, 0, 0]);
        crate::udf::stamp_tag(&mut block, 6, (446 - 16) as u16, lbn);
        block
    }

    /// File set block with the root ICB (one block, relative 10,
    /// reference 0). Copied (see [`uf_recognition`]).
    fn uf_fsd() -> Vec<u8> {
        let mut block = vec![0u8; UF_SIZE as usize];
        block[400..404].copy_from_slice(&UF_SIZE.to_le_bytes());
        block[404..408].copy_from_slice(&10u32.to_le_bytes());
        crate::udf::stamp_tag(&mut block, 256, (UF_SIZE - 16) as u16, 8);
        block
    }

    /// Extended file entry with `data` embedded (information length =
    /// data length) and file type `ftype`, claiming
    /// partition-relative `rel`. Copied (see [`uf_recognition`]).
    fn uf_ext(rel: u32, data: &[u8], ftype: u8) -> Vec<u8> {
        let mut block = vec![0u8; UF_SIZE as usize];
        block[27] = ftype;
        block[16 + 18..16 + 20].copy_from_slice(&3u16.to_le_bytes());
        block[56..64].copy_from_slice(&(data.len() as u64).to_le_bytes());
        block[208..212].copy_from_slice(&0u32.to_le_bytes());
        block[212..216].copy_from_slice(&(data.len() as u32).to_le_bytes());
        block[216..216 + data.len()].copy_from_slice(data);
        crate::udf::stamp_tag(&mut block, 266, (UF_SIZE - 16) as u16, rel);
        block
    }

    /// One FID record: characteristics `char`, ICB (one block, `lbn`),
    /// `name` bytes, location `loc`, CRC fixed, padded to 4. Copied
    /// (see [`uf_recognition`]).
    fn uf_fid(characteristics: u8, lbn: u32, name: &[u8], loc: u32) -> Vec<u8> {
        let body = 38 + name.len();
        let total = body + (4 - body % 4) % 4;
        let mut record = vec![0u8; total];
        record[16..18].copy_from_slice(&1u16.to_le_bytes());
        record[18] = characteristics;
        record[19] = name.len() as u8;
        record[20..24].copy_from_slice(&UF_SIZE.to_le_bytes());
        record[24..28].copy_from_slice(&lbn.to_le_bytes());
        record[38..38 + name.len()].copy_from_slice(name);
        crate::udf::stamp_tag(&mut record, 257, (total - 16) as u16, loc);
        record
    }

    /// One 12-byte ECMA timestamp: type 1 with `quarters`
    /// quarter-hour offset, then year and the civil fields (month,
    /// day, hour, minute, second, centiseconds, hundreds;
    /// microseconds stays zero). Copied from the `udf/reader.rs`
    /// symlink test builders (see [`uf_recognition`]).
    fn uf_stamp(quarters: u16, year: u16, fields: [u8; 7]) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..2].copy_from_slice(&(0x1000 | (quarters & 0x0FFF)).to_le_bytes());
        out[2..4].copy_from_slice(&year.to_le_bytes());
        out[4..11].copy_from_slice(&fields);
        out
    }

    /// One prefixed-shape symlink component: type, length,
    /// identifier, zero padding to a 4-byte boundary. Copied (see
    /// [`uf_recognition`]).
    fn uf_comp(comp_type: u8, ident: &[u8]) -> Vec<u8> {
        let mut out = vec![comp_type, ident.len() as u8];
        out.extend_from_slice(ident);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    /// Full synthetic volume: recognition, anchor, six-descriptor
    /// main sequence, file set at relative 8 and root entry at
    /// relative 10 embedding `root`. Extra `(absolute block, bytes)`
    /// pairs land after the fixed layout.
    fn uf_volume(root: &[u8], extra: &[(u32, Vec<u8>)]) -> VecVolume {
        let mut total_blocks = UF_PART_AT + 16;
        for (abs, _) in extra {
            total_blocks = total_blocks.max(abs.saturating_add(1));
        }
        let mut volume = VecVolume::new(u64::from(total_blocks) * u64::from(UF_SIZE), 512)
            .expect("the fixture fits in RAM");
        volume
            .write_all_at(32768, &uf_recognition())
            .expect("the recognition fits");
        let mut put = |abs: u32, bytes: &[u8]| {
            volume
                .write_all_at(u64::from(abs) * u64::from(UF_SIZE), bytes)
                .expect("the block fits");
        };
        put(UF_ANCHOR_AT, &uf_anchor());
        put(96, &uf_skipped(96, 1));
        put(97, &uf_logical(97));
        put(98, &uf_partition(98));
        put(99, &uf_skipped(99, 7));
        put(100, &uf_skipped(100, 4));
        put(101, &uf_skipped(101, 8));
        put(UF_PART_AT + 8, &uf_fsd());
        put(UF_PART_AT + 10, &uf_ext(10, root, 4));
        for (abs, bytes) in extra {
            put(*abs, bytes);
        }
        volume
    }

    #[test]
    fn udf_source_carries_links_modes_and_stamps() {
        use std::time::Duration;
        use std::time::UNIX_EPOCH;

        // Root holds FILE.TXT (9 bytes), SUB/ (with UP pointing at
        // `../FILE.TXT` in the prefixed shape, permission word
        // 0x1CA5 and known stamps) and LINK (pointing at FILE.TXT in
        // the bare shape with a zero permission word). Listings carry
        // every adapter field, and the tree copies end to end with
        // both links recreated.
        let mut up_body = uf_comp(3, &[]);
        up_body.extend_from_slice(&uf_comp(
            5,
            &[8, b'F', b'I', b'L', b'E', b'.', b'T', b'X', b'T'],
        ));
        let mut up_data = (up_body.len() as u16).to_le_bytes().to_vec();
        up_data.extend_from_slice(&up_body);
        let mut up_block = uf_ext(14, &up_data, 12);
        up_block[44..48].copy_from_slice(&0x1CA5u32.to_le_bytes());
        up_block[80..92].copy_from_slice(&uf_stamp(0, 2023, [11, 14, 22, 13, 20, 0, 0]));
        up_block[92..104].copy_from_slice(&uf_stamp(0, 2024, [2, 29, 12, 34, 56, 0, 0]));
        crate::udf::stamp_tag(&mut up_block, 266, (UF_SIZE - 16) as u16, 14);
        let bare = vec![
            5, 9, 1, 0, 8, b'F', b'I', b'L', b'E', b'.', b'T', b'X', b'T',
        ];
        let mut sub = uf_fid(0x0A, 12, &[], 12);
        sub.extend_from_slice(&uf_fid(0x00, 14, &[8, b'U', b'P'], 12));
        let mut root = uf_fid(0x0A, 10, &[], 10);
        root.extend_from_slice(&uf_fid(
            0x00,
            11,
            &[8, b'F', b'I', b'L', b'E', b'.', b'T', b'X', b'T'],
            10,
        ));
        root.extend_from_slice(&uf_fid(0x02, 12, &[8, b'S', b'U', b'B'], 10));
        root.extend_from_slice(&uf_fid(0x00, 13, &[8, b'L', b'I', b'N', b'K'], 10));
        // Fixture file and directory entries need usable permission
        // words: the copy applies them, and a zero word would chmod
        // the file unreadable and the directory untraversable for a
        // non-root tester. LINK keeps its zero word (symlinks carry no
        // metadata — setting times through a link would touch its
        // target).
        let mut file_block = uf_ext(11, b"udf-bytes", 5);
        file_block[44..48].copy_from_slice(&0x1884u32.to_le_bytes());
        crate::udf::stamp_tag(&mut file_block, 266, (UF_SIZE - 16) as u16, 11);
        let mut sub_block = uf_ext(12, &sub, 4);
        sub_block[44..48].copy_from_slice(&0x1CA5u32.to_le_bytes());
        crate::udf::stamp_tag(&mut sub_block, 266, (UF_SIZE - 16) as u16, 12);
        let volume = uf_volume(
            &root,
            &[
                (UF_PART_AT + 11, file_block),
                (UF_PART_AT + 12, sub_block),
                (UF_PART_AT + 13, uf_ext(13, &bare, 12)),
                (UF_PART_AT + 14, up_block),
            ],
        );
        let reader = UdfReader::open(Box::new(volume)).expect("the fixture opens");
        let source = UdfSource::new(reader);
        // Listings keep store order and carry every field: LINK has
        // the decoded target with a zero-word mode and no stamps (a
        // zeroed stamp cannot place).
        let listed = source.root_entries().expect("the root lists");
        assert_eq!(
            listed
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>(),
            [b"FILE.TXT".to_vec(), b"SUB".to_vec(), b"LINK".to_vec()]
        );
        assert_eq!(listed[0].size, 9);
        assert_eq!(listed[0].link, None);
        assert_eq!(listed[2].link, Some(b"FILE.TXT".to_vec()));
        assert!(!listed[2].is_dir && listed[2].size == 0);
        assert_eq!(listed[2].mode, Some(0));
        assert_eq!(listed[2].modified, None);
        // UP carries the target, the mapped mode and both stamps
        // (epochs per `date -u`, not per the converter).
        let children = source.child_entries(&[b"SUB".to_vec()]).expect("SUB lists");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].link, Some(b"../FILE.TXT".to_vec()));
        assert_eq!(children[0].mode, Some(0o755));
        assert_eq!(
            children[0].modified,
            Some(UNIX_EPOCH + Duration::new(1_709_210_096, 0))
        );
        assert_eq!(
            children[0].accessed,
            Some(UNIX_EPOCH + Duration::new(1_700_000_000, 0))
        );
        // End to end: both links recreate, the file lands with its
        // bytes, and only its bytes count.
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = WarnLog { warns: Vec::new() };
        let summary = super::super::walk(
            &source,
            scratch.path(),
            &super::super::CopyOptions {
                free_bytes: None,
                replacer: None,
            },
            &mut progress,
        )
        .expect("the UDF link tree copies");
        assert_eq!(
            summary,
            super::super::Summary {
                directories: 1,
                files: 3,
                bytes: 9,
                renamed: 0,
            }
        );
        assert!(
            progress.warns.is_empty(),
            "inside links warn nothing: {:?}",
            progress.warns
        );
        assert_eq!(
            std::fs::read(scratch.path().join("FILE.TXT")).expect("the file reads back"),
            b"udf-bytes"
        );
        assert_eq!(
            std::fs::read_link(scratch.path().join("LINK")).expect("LINK reads"),
            std::path::Path::new("FILE.TXT")
        );
        assert_eq!(
            std::fs::read_link(scratch.path().join("SUB").join("UP")).expect("UP reads"),
            std::path::Path::new("../FILE.TXT")
        );
    }
}
