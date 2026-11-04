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
//! the reader has them (ISO `PX`/`TF`; UDF entries carry `None` — the
//! UDF reader parses neither extended attributes nor timestamps, and
//! UDF on a stick is a data volume, so carrying the gap is the honest
//! choice for now — the UDF reader itself is untouched). Link targets
//! stay out (slice 4); an entry the adapters cannot size as data
//! still refuses here, before any byte moves, instead of copying
//! something wrong.

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crate::error::CoreError;
use crate::error::Result;
use crate::iso::IsoReader;
use crate::iso::rock::RockTime;
use crate::udf::UdfReader;

/// One listed entry: name, kind, size and metadata. Link targets stay
/// absent (slice 4); ownership never rides along (needs privileges —
/// see [`DestDir::apply_metadata`](super::DestDir::apply_metadata)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// File name as stored: raw identifier bytes on ISO
    /// ([`file_name`](crate::iso::reader::Entry::file_name)), UTF-8 on
    /// UDF.
    pub name: Vec<u8>,
    /// True for directories.
    pub is_dir: bool,
    /// File size in bytes; 0 for directories.
    pub size: u64,
    /// POSIX mode from `PX` (file type bits included — the destination
    /// masks); `None` where the record carries no `PX`, and always on
    /// UDF.
    pub mode: Option<u32>,
    /// Modification time from `TF`, converted to UTC; `None` where the
    /// record carries none, where conversion refuses, and always on
    /// UDF.
    pub modified: Option<SystemTime>,
    /// Last-access time from `TF`, converted like [`modified`](Entry::modified).
    pub accessed: Option<SystemTime>,
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
/// them (preferred on a SUSP volume). Symlinks refuse at listing
/// time: they are never followed, and a silent skip would lose data.
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

    /// Translate one reader listing, refusing symlink entries: they
    /// are never followed, and skipping them would lose data. Modes
    /// ride whole (the destination masks); stamps convert to UTC, and
    /// a stamp the converter cannot place reads as absent.
    fn translate(&self, entries: Vec<crate::iso::reader::Entry>) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        for entry in &entries {
            if entry.symlink_target.is_some() {
                return Err(CoreError::invalid(format!(
                    "copy refuses '{}': it is a symbolic link, and this slice copies data only",
                    String::from_utf8_lossy(&entry.file_name())
                )));
            }
            out.push(Entry {
                name: entry.file_name(),
                is_dir: entry.is_dir,
                size: if entry.is_dir {
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
/// Entries the reader cannot open as data (symlinks, FIFOs and the
/// rest — each refuses with its kind named) fail the listing that
/// contains them: failing fast before any byte moves, exactly like
/// the ISO side's symlink refusal.
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

    /// Translate one reader listing, sizing files through `open_file`
    /// (which is also what refuses symlinks and special files with
    /// their kind named). Modes and stamps stay `None`: the UDF
    /// reader parses neither extended attributes nor timestamps (see
    /// the module docs).
    fn translate(&self, entries: Vec<crate::udf::reader::Entry>) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        for entry in &entries {
            let size = if entry.is_directory {
                0
            } else {
                self.reader.open_file(entry)?.len()
            };
            out.push(Entry {
                name: entry.name.clone().into_bytes(),
                is_dir: entry.is_directory,
                size,
                mode: None,
                modified: None,
                accessed: None,
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
            &super::super::CopyOptions { free_bytes: None },
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
            &super::super::CopyOptions { free_bytes: None },
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
            &super::super::CopyOptions { free_bytes: None },
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
            &super::super::CopyOptions { free_bytes: None },
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
}
