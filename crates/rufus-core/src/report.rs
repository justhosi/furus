//! The S16 image report: what an image is, in one plain-data struct
//! (slice 1 of 6).
//!
//! This is the analogue of the Rufus `img_report`: [`analyze`] probes a
//! [`Volume`](crate::fs::Volume) for ISO9660 first (the `CD001` magic at
//! byte `0x8001`, the same check the ISO reader uses) and UDF second
//! (the sector-256 anchor probe), fills the label candidates and the
//! [`ImageReport`] shape, and records whether the shared tree index hit
//! its caps. Anything unrecognised is `"raw"`, never an error — only a
//! reader that fails on a volume that probed positive is a real error.
//!
//! Slices 2-6 fill the rest: slice 2 the Windows fields (`is_windows`,
//! `windows_version`, `build`, `is_windows_to_go`, `wim_images`), slices
//! 3-4 the distro and persistence fields, slice 5 the bootloader fields
//! (`has_efi`, `has_bios`, `has_grub`, `has_syslinux` and the versions),
//! and slice 6 the CLI wiring. Every one of those fields exists here
//! already so [`ImageReport`] stays stable across the slices.
//!
//! [`TreeIndex`] is the case-insensitive tree both readers share: later
//! slices ask `has("/sources/boot.wim")`-style questions without
//! re-walking. It is capped ([`MAX_ENTRIES`], [`MAX_DEPTH`]) so a hostile
//! image cannot blow up the index; a cap hit sets [`truncated`](ImageReport::truncated)
//! instead of failing. (The walk itself already materialises the whole
//! tree, bounded by each reader's own depth limit, so the caps bound
//! only what is retained.) An absent path then means "not seen within
//! the cap", never "proven absent" — the honest analogue of Rufus,
//! which walks without a cap.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use serde::Serialize;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::iso::IsoReader;
use crate::udf::UdfReader;

/// Cap on indexed entries: past this the index stops growing and the
/// report records [`truncated`](ImageReport::truncated) instead of
/// failing the analysis.
pub const MAX_ENTRIES: usize = 200_000;

/// Cap on indexed path depth in components (`/A/B` is depth 2, `/` is
/// depth 0): deeper entries are skipped and the report records
/// [`truncated`](ImageReport::truncated). Both readers already refuse
/// walks past their own depth bounds, so this is defence in depth.
pub const MAX_DEPTH: usize = 32;

/// Offset of the ISO9660 descriptor magic: byte 1 of sector 16
/// (derived from the ISO reader's own sector constants).
const ISO_MAGIC_OFFSET: u64 =
    crate::iso::FIRST_DESCRIPTOR_SECTOR as u64 * crate::iso::SECTOR_BYTES as u64 + 1;

/// The ISO9660 descriptor magic (`CD001` at [`ISO_MAGIC_OFFSET`]).
const ISO_MAGIC: [u8; 5] = *b"CD001";

/// The label candidates of an image, in preference order: the ISO9660
/// primary volume descriptor label, the highest-level Joliet
/// supplementary label when one exists, and the UDF volume label when
/// the image is UDF.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Labels {
    /// ISO9660 primary volume descriptor label (slice 1 fills this on
    /// ISO images).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<String>,
    /// Highest-level Joliet supplementary label, if any (slice 1 fills
    /// this; ties keep the first descriptor, as the ISO reader does).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub joliet: Option<String>,
    /// UDF volume label, if the image is UDF (slice 1 fills this on
    /// UDF images).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udf: Option<String>,
}

impl Labels {
    /// The first non-empty candidate: primary, then Joliet, then UDF.
    /// Empty strings never win, so a blank descriptor cannot shadow a
    /// real label behind it.
    #[must_use]
    pub fn best(&self) -> Option<&str> {
        for candidate in [&self.primary, &self.joliet, &self.udf] {
            if let Some(label) = candidate
                && !label.is_empty()
            {
                return Some(label.as_str());
            }
        }
        None
    }
}

/// One Windows edition from a WIM XML: slice 2/6 fills these; the type
/// exists now so [`ImageReport`] is stable across the slices.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WimImage {
    /// 1-based image index inside the WIM.
    pub index: u32,
    /// The `<NAME>` text, when the XML carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The `<DISPLAYNAME>` text, when the XML carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The `<DESCRIPTION>` text, when the XML carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// What an image is, as plain data (serialisable for the golden JSON).
/// Slice 1 fills `kind`, `is_iso`, `is_udf`, `labels` and `truncated`;
/// slices 2-6 fill the rest, each documented on its field.
///
/// `Default` exists for struct-update syntax only: it yields `kind: ""`,
/// not `"raw"` — only [`analyze`] assigns the family label.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageReport {
    /// The image family label: `"iso"` when bytes `0x8001..0x8006`
    /// read `CD001`, `"udf"` when the sector-256 anchor probe
    /// validates, `"raw"` for anything else. An image carrying both
    /// signals reads as `"iso"`: the ISO probe runs first.
    pub kind: String,
    /// True when the ISO probe matched (see [`kind`](Self::kind)).
    pub is_iso: bool,
    /// True when the UDF anchor probe validated and no ISO magic
    /// matched: ISO wins over UDF, so a bridge image carrying both
    /// reads as ISO with this false and [`labels`](Self::labels)
    /// `udf` unset.
    pub is_udf: bool,
    /// True when slice 2/6 proves a Windows payload (this slice: always
    /// false).
    pub is_windows: bool,
    /// Windows major version, e.g. `"11"` (slice 2/6 fills this).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_version: Option<String>,
    /// Windows build number, e.g. `22631` (slice 2/6 fills this).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<u32>,
    /// True for a Windows To Go layout (slice 2/6 fills this).
    pub is_windows_to_go: bool,
    /// True when an EFI boot path was seen (slice 5/6 fills this).
    pub has_efi: bool,
    /// True when a BIOS boot path was seen (slice 5/6 fills this).
    pub has_bios: bool,
    /// True when GRUB was seen (slice 5/6 fills this).
    pub has_grub: bool,
    /// GRUB version text, when known (slice 5/6 fills this).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grub_version: Option<String>,
    /// True when Syslinux or Isolinux was seen (slice 5/6 fills this).
    pub has_syslinux: bool,
    /// Syslinux version text, when known (slice 5/6 fills this).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syslinux_version: Option<String>,
    /// Linux distribution identifier, e.g. `"ubuntu"` (slices 3-4/6
    /// fill this).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distro: Option<String>,
    /// Persistence mode label (slice 4/6 fills this).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistence: Option<String>,
    /// One entry per Windows edition from the WIM XML (slice 2/6 fills
    /// this).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wim_images: Vec<WimImage>,
    /// Label candidates from the volume descriptors (slice 1 fills
    /// these). ISO wins over UDF: on a bridge image only `primary`
    /// and `joliet` fill, `udf` stays `None`.
    pub labels: Labels,
    /// True when the tree index hit [`MAX_ENTRIES`] or [`MAX_DEPTH`],
    /// or when the underlying walk refused partway: an absent path
    /// then means "not seen within the cap", never "proven absent".
    /// This is the honest analogue of Rufus, which walks with no cap.
    pub truncated: bool,
}

/// One indexed tree entry: the absolute path plus the shape the later
/// slices' rules need, without re-walking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Absolute `/`-separated path exactly as the reader `walk()`
    /// produced it (`/` for the root).
    pub path: String,
    /// True for directories, false for files (and for anything else
    /// the walk lists).
    pub is_dir: bool,
    /// File length in bytes for files that report one; `None` for
    /// directories and for files whose length is unknown (a UDF entry
    /// whose metadata refuses to open).
    pub size: Option<u64>,
}

/// The case-insensitive tree index both readers share, so later slices
/// ask path questions without re-walking. Keys are the path lowercased
/// with `/` separators (ASCII only: image paths are ASCII in
/// practice); a leading `/` is optional on lookup.
#[derive(Debug, Clone, Default)]
pub struct TreeIndex {
    /// Nodes in walk order (the root first).
    nodes: Vec<Node>,
    /// Lowercased path to the first node index carrying it (a
    /// case-colliding second spelling still lists in [`nodes`](Self::nodes),
    /// but lookups keep the first).
    by_lower: HashMap<String, usize>,
    /// True once [`MAX_ENTRIES`] or [`MAX_DEPTH`] stopped an insert,
    /// or the underlying walk refused partway.
    truncated: bool,
}

/// Normalised lookup key: one optional leading `/` dropped, ASCII
/// lowercased (no Unicode folding: image paths are ASCII in practice).
fn normalize(path: &str) -> String {
    path.strip_prefix('/').unwrap_or(path).to_ascii_lowercase()
}

/// Path depth in components: `/` is 0, `/A` is 1, `/A/B` is 2.
fn path_depth(path: &str) -> usize {
    path.split('/').filter(|part| !part.is_empty()).count()
}

impl TreeIndex {
    /// Index the ISO reader's walked tree. The walk returns all or
    /// nothing, so a refused walk yields an empty index marked
    /// truncated; the caps ([`MAX_ENTRIES`], [`MAX_DEPTH`]) mark the
    /// index the same way instead of failing.
    pub fn from_iso(reader: &IsoReader) -> TreeIndex {
        let mut index = TreeIndex::default();
        let walked = match reader.walk() {
            Ok(walked) => walked,
            Err(_) => {
                index.truncated = true;
                return index;
            }
        };
        for (path, entry) in walked {
            if index.nodes.len() >= MAX_ENTRIES {
                index.truncated = true;
                break;
            }
            let size = if entry.is_dir {
                None
            } else {
                Some(u64::from(entry.data_len))
            };
            index.push(Node {
                path,
                is_dir: entry.is_dir,
                size,
            });
        }
        index
    }

    /// Index the UDF reader's walked tree, with the same all-or-nothing
    /// refusal and cap contract as [`from_iso`](Self::from_iso). File
    /// sizes come from the entry metadata (never from file contents);
    /// an entry whose metadata refuses to open indexes with `size`
    /// `None`.
    pub fn from_udf(reader: &UdfReader) -> TreeIndex {
        let mut index = TreeIndex::default();
        let walked = match reader.walk() {
            Ok(walked) => walked,
            Err(_) => {
                index.truncated = true;
                return index;
            }
        };
        for (path, entry) in walked {
            if index.nodes.len() >= MAX_ENTRIES {
                index.truncated = true;
                break;
            }
            let size = if entry.is_directory {
                None
            } else {
                reader.open_file(&entry).map(|file| file.len()).ok()
            };
            index.push(Node {
                path,
                is_dir: entry.is_directory,
                size,
            });
        }
        index
    }

    /// Insert one node: entries deeper than [`MAX_DEPTH`] are skipped
    /// (their descendants are deeper still, so whole subtrees drop)
    /// and mark the index truncated.
    fn push(&mut self, node: Node) {
        if path_depth(&node.path) > MAX_DEPTH {
            self.truncated = true;
            return;
        }
        let key = normalize(&node.path);
        let at = self.nodes.len();
        self.nodes.push(node);
        self.by_lower.entry(key).or_insert(at);
    }

    /// The node at `path` (leading `/` optional, any ASCII case), when
    /// the index holds it.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&Node> {
        let key = normalize(path);
        self.by_lower.get(&key).and_then(|at| self.nodes.get(*at))
    }

    /// True when [`get`](Self::get) would find `path`.
    #[must_use]
    pub fn has(&self, path: &str) -> bool {
        self.get(path).is_some()
    }

    /// Every indexed node in walk order, root first.
    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// True when the index stopped early: an entry or depth cap hit, or
    /// the underlying walk refused partway.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The first node (in walk order) whose last path component matches
    /// `file_name` ASCII-case-insensitively, for rules that only know a
    /// file name like `bootmgr`. The hit may be a directory: callers
    /// that need a file must check [`is_dir`](Node::is_dir) themselves
    /// (the index never filters; slice 3 needs both behaviours).
    #[must_use]
    pub fn find_name(&self, file_name: &str) -> Option<&Node> {
        self.nodes.iter().find(|node| {
            let last = node.path.rsplit('/').next().unwrap_or("");
            last.eq_ignore_ascii_case(file_name)
        })
    }
}

/// True when bytes `0x8001..0x8006` read `CD001`. Size-guarded: a
/// volume shorter than the window simply has no magic and reads as
/// absent. An I/O refusal at a covered window is a real error and is
/// returned: the bytes were supposed to be there.
fn has_iso_magic(volume: &dyn Volume) -> Result<bool> {
    let end = ISO_MAGIC_OFFSET
        .checked_add(ISO_MAGIC.len() as u64)
        .ok_or_else(|| {
            CoreError::invalid("iso magic window overflows the byte offset arithmetic")
        })?;
    if volume.total_bytes() < end {
        return Ok(false);
    }
    let mut magic = [0u8; ISO_MAGIC.len()];
    volume.read_exact_at(ISO_MAGIC_OFFSET, &mut magic)?;
    Ok(magic == ISO_MAGIC)
}

/// The highest-level Joliet supplementary label, if any (ties keep the
/// first descriptor in sequence order, exactly as the ISO reader
/// selects the walked tree).
fn highest_joliet_label(reader: &IsoReader) -> Option<String> {
    let mut best: Option<(u8, &str)> = None;
    for supplementary in reader.supplementary() {
        if let Some(level) = supplementary.joliet_level {
            let higher = match best {
                Some((top, _)) => level > top,
                None => true,
            };
            if higher {
                best = Some((level, supplementary.label.as_str()));
            }
        }
    }
    best.map(|(_, label)| label.to_string())
}

/// Analyse `volume`: probe ISO, then UDF, else report `"raw"`.
///
/// A reader that fails on a volume that probed positive is a real
/// error and is returned (never silently downgraded to `"raw"`).
/// Only ISO and UDF are in scope: a `.wim`, VHD or anything else
/// unrecognised is `"raw"` for now, with every flag false.
///
/// Cost note: the tree is walked here and the index then dropped, so a
/// later slice that needs the index pays for the walk twice (on UDF
/// that means an `open_file` per file, again). Slice 2 must decide
/// between returning an `Analysis { report, index }` and a cached walk;
/// the return type stays [`ImageReport`] until then.
pub fn analyze(volume: Box<dyn Volume>) -> Result<ImageReport> {
    if has_iso_magic(volume.as_ref())? {
        let reader = IsoReader::open(volume)?;
        let index = TreeIndex::from_iso(&reader);
        return Ok(ImageReport {
            kind: "iso".to_string(),
            is_iso: true,
            labels: Labels {
                primary: Some(reader.primary().label.clone()),
                joliet: highest_joliet_label(&reader),
                udf: None,
            },
            truncated: index.is_truncated(),
            ..ImageReport::default()
        });
    }
    if crate::udf::anchor::probe(volume.as_ref()).is_ok() {
        let reader = UdfReader::open(volume)?;
        let index = TreeIndex::from_udf(&reader);
        return Ok(ImageReport {
            kind: "udf".to_string(),
            is_udf: true,
            labels: Labels {
                primary: None,
                joliet: None,
                udf: Some(reader.volume_label().to_string()),
            },
            truncated: index.is_truncated(),
            ..ImageReport::default()
        });
    }
    Ok(ImageReport {
        kind: "raw".to_string(),
        ..ImageReport::default()
    })
}

/// Analyse the regular file at `path`: open it read-only exactly the
/// way [`open_image`](crate::image::open_image) does (a
/// [`FileVolume`](crate::fs::FileVolume)), then [`analyze`] it.
pub fn analyze_file(path: &Path) -> Result<ImageReport> {
    let volume = crate::fs::FileVolume::open(path)?;
    analyze(Box::new(volume))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::iso::SECTOR_BYTES;
    use crate::iso::record::FLAG_DIRECTORY;
    use crate::iso::record::RECORD_FIXED_LEN;

    /// Sectors of the shared fixture images (32 sectors total).
    const IMAGE_SECTORS: u32 = 32;
    /// Primary-tree root directory sector.
    const ROOT_SECTOR: u32 = 20;
    /// Joliet-tree root directory sector.
    const JOLIET_ROOT_SECTOR: u32 = 25;
    /// `SOURCES/` directory sector (primary-tree fixture).
    const SOURCES_SECTOR: u32 = 21;
    /// `SOURCES/BOOT.WIM` content sector (primary-tree fixture).
    const BOOT_WIM_SECTOR: u32 = 22;

    /// Encode one directory record, mirroring the on-disk layout the
    /// parser reads (both-endian words, zero date, sequence 1, the
    /// even-length pad). Kept local: this is the second copy of that
    /// code (`iso/reader.rs` tests hold the first), deliberately not
    /// extracted yet — extract a shared fixture module if a third
    /// consumer appears.
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

    /// Encode `text` as UCS-2BE bytes (BMP-only fixtures, so every
    /// character is one unit). Kept local, same as above.
    fn ucs2(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_be_bytes());
        }
        out
    }

    /// Primary-descriptor sector with `label` and the root at
    /// (`root_extent`, `root_len`). Kept local, same as above.
    fn primary_sector(label: &str, root_extent: u32, root_len: u32) -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = 1;
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
        sector[120..122].copy_from_slice(&1u16.to_le_bytes());
        sector[122..124].copy_from_slice(&1u16.to_be_bytes());
        sector[124..126].copy_from_slice(&1u16.to_le_bytes());
        sector[126..128].copy_from_slice(&1u16.to_be_bytes());
        sector[128..130].copy_from_slice(&2048u16.to_le_bytes());
        sector[130..132].copy_from_slice(&2048u16.to_be_bytes());
        let root = encode_record(root_extent, root_len, FLAG_DIRECTORY, b"\x00");
        sector[156..156 + root.len()].copy_from_slice(&root);
        sector
    }

    /// Supplementary-descriptor sector: UCS-2BE volume identifier
    /// (space-padded like real mastering tools), the given escape
    /// opening, and the root at (`root_extent`, `root_len`). Kept
    /// local, same as above.
    fn joliet_sector(
        label: &str,
        escape: &[u8],
        root_extent: u32,
        root_len: u32,
    ) -> [u8; SECTOR_BYTES] {
        let mut sector = primary_sector("SUPP", root_extent, root_len);
        sector[0] = 2;
        let mut field = [0u8; 32];
        for pair in field.chunks_mut(2) {
            pair.copy_from_slice(&0x0020u16.to_be_bytes());
        }
        let encoded = ucs2(label);
        let take = encoded.len().min(32);
        field[..take].copy_from_slice(&encoded[..take]);
        sector[40..72].copy_from_slice(&field);
        for byte in sector.iter_mut().skip(88).take(32) {
            *byte = 0;
        }
        let take_escape = escape.len().min(32);
        sector[88..88 + take_escape].copy_from_slice(&escape[..take_escape]);
        sector
    }

    /// Terminator sector. Kept local, same as above.
    fn terminator_sector() -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = 255;
        sector[1..6].copy_from_slice(b"CD001");
        sector[6] = 1;
        sector
    }

    /// Pack records back to back at the start of one zeroed sector.
    /// Kept local, same as above.
    fn dir_sector(records: &[Vec<u8>]) -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        let mut offset = 0;
        for record in records {
            sector[offset..offset + record.len()].copy_from_slice(record);
            offset += record.len();
        }
        sector
    }

    /// Write `writes` as (sector, bytes) pairs over a zeroed
    /// 32-sector image.
    fn image_with(writes: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut image = vec![0u8; IMAGE_SECTORS as usize * SECTOR_BYTES];
        for (sector, bytes) in writes {
            let base = *sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(&bytes[..]);
        }
        image
    }

    /// Fixture for the label test: primary label `TESTVOL` with an
    /// empty root, plus a level-3 Joliet supplementary labelled
    /// `Joliet Vol` with its own empty root.
    fn label_fixture_bytes() -> Vec<u8> {
        image_with(&[
            (
                16,
                primary_sector("TESTVOL", ROOT_SECTOR, SECTOR_BYTES as u32).to_vec(),
            ),
            (
                17,
                joliet_sector(
                    "Joliet Vol",
                    b"%/E",
                    JOLIET_ROOT_SECTOR,
                    SECTOR_BYTES as u32,
                )
                .to_vec(),
            ),
            (18, terminator_sector().to_vec()),
            (
                ROOT_SECTOR,
                dir_sector(&[
                    encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                    encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                ])
                .to_vec(),
            ),
            (
                JOLIET_ROOT_SECTOR,
                dir_sector(&[
                    encode_record(
                        JOLIET_ROOT_SECTOR,
                        SECTOR_BYTES as u32,
                        FLAG_DIRECTORY,
                        b"\x00",
                    ),
                    encode_record(
                        JOLIET_ROOT_SECTOR,
                        SECTOR_BYTES as u32,
                        FLAG_DIRECTORY,
                        b"\x01",
                    ),
                ])
                .to_vec(),
            ),
        ])
    }

    /// Fixture for the index test: a primary-only tree holding
    /// `SOURCES/BOOT.WIM` (12 content bytes).
    fn tree_fixture_bytes() -> Vec<u8> {
        image_with(&[
            (
                16,
                primary_sector("TESTVOL", ROOT_SECTOR, SECTOR_BYTES as u32).to_vec(),
            ),
            (17, terminator_sector().to_vec()),
            (
                ROOT_SECTOR,
                dir_sector(&[
                    encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                    encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                    encode_record(
                        SOURCES_SECTOR,
                        SECTOR_BYTES as u32,
                        FLAG_DIRECTORY,
                        b"SOURCES",
                    ),
                ])
                .to_vec(),
            ),
            (
                SOURCES_SECTOR,
                dir_sector(&[
                    encode_record(SOURCES_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                    encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                    encode_record(BOOT_WIM_SECTOR, 12, 0, b"BOOT.WIM;1"),
                ])
                .to_vec(),
            ),
            (BOOT_WIM_SECTOR, b"wim-content!".to_vec()),
        ])
    }

    /// A memory volume holding `bytes`.
    fn memory_volume(bytes: &[u8]) -> VecVolume {
        let mut volume = VecVolume::new(bytes.len() as u64, 512).expect("the fixture fits in RAM");
        if !bytes.is_empty() {
            volume.write_all_at(0, bytes).expect("the fixture writes");
        }
        volume
    }

    // `from_udf` and the `analyze` UDF arm have no coverage here: the
    // minimal UDF fixture builder lives private inside `udf/reader.rs`
    // tests, and duplicating it is out of scope. A shared UDF fixture
    // is owed to a later slice.

    #[test]
    fn iso_volume_reports_kind_and_labels() {
        let report =
            analyze(Box::new(memory_volume(&label_fixture_bytes()))).expect("the fixture analyses");
        assert_eq!(report.kind, "iso");
        assert!(report.is_iso);
        assert!(!report.is_udf);
        assert!(!report.is_windows);
        assert_eq!(report.labels.primary.as_deref(), Some("TESTVOL"));
        assert_eq!(report.labels.joliet.as_deref(), Some("Joliet Vol"));
        assert_eq!(report.labels.udf, None);
        assert_eq!(report.labels.best(), Some("TESTVOL"));
        assert!(!report.truncated);
        assert!(report.wim_images.is_empty());
    }

    #[test]
    fn short_and_blank_volumes_are_raw_without_error() {
        for len in [0u64, 1, 100] {
            let volume = VecVolume::new(len, 512).expect("the fixture fits in RAM");
            let report = analyze(Box::new(volume)).expect("a short volume never errors");
            assert_eq!(report.kind, "raw", "length {len}");
            assert!(!report.is_iso);
            assert!(!report.is_udf);
            assert!(!report.is_windows);
            assert_eq!(report.labels, Labels::default());
            assert!(!report.truncated);
        }
        // 64 KiB of zeroes covers both probe windows but matches
        // neither magic: the UDF probe refuses, and the volume is raw.
        let volume = VecVolume::new(65536, 512).expect("the fixture fits in RAM");
        let report = analyze(Box::new(volume)).expect("a blank volume never errors");
        assert_eq!(report.kind, "raw");
        assert!(!report.is_iso);
        assert!(!report.is_udf);
    }

    #[test]
    fn tree_index_is_case_insensitive_and_slash_tolerant() {
        let reader = IsoReader::open(Box::new(memory_volume(&tree_fixture_bytes())))
            .expect("the fixture opens");
        let index = TreeIndex::from_iso(&reader);
        assert!(!index.is_truncated());
        assert!(index.has("sources/boot.wim"));
        assert!(index.has("/Sources/Boot.Wim"));
        assert!(index.has("/SOURCES/BOOT.WIM"));
        assert!(!index.has("sources/missing.wim"));
        let node = index.get("SOURCES/BOOT.WIM").expect("the file indexes");
        assert_eq!(node.path, "/SOURCES/BOOT.WIM");
        assert!(!node.is_dir);
        assert_eq!(node.size, Some(12));
        let found = index.find_name("boot.wim").expect("the name search hits");
        assert_eq!(found.path, "/SOURCES/BOOT.WIM");
        assert!(index.find_name("missing.wim").is_none());
        // Directory entries carry no size: a directory's data length is
        // sector bookkeeping, not a file length.
        let dir = index.get("sources").expect("the directory indexes");
        assert_eq!(dir.path, "/SOURCES");
        assert!(dir.is_dir);
        assert_eq!(dir.size, None);
    }

    #[test]
    fn depth_cap_skips_the_node_and_marks_truncated() {
        let mut index = TreeIndex::default();
        // `"D/".repeat(MAX_DEPTH)` alone yields exactly `MAX_DEPTH`
        // components, which still fits: one more component is appended
        // so the path genuinely exceeds the cap.
        index.push(Node {
            path: format!("/{}X", "D/".repeat(MAX_DEPTH)),
            is_dir: true,
            size: None,
        });
        assert!(index.nodes().is_empty());
        assert!(index.is_truncated());
        // The 200_000-entry cap is deliberately not exercised: the
        // fixture would be too heavy for a unit test.
    }

    #[test]
    fn iso_magic_with_a_broken_sequence_is_an_error() {
        // Only the magic, no valid sector-16 sequence: the probe is
        // positive, so the refusing reader must surface as an error,
        // never as `"raw"`.
        let mut volume = VecVolume::new(65536, 512).expect("the fixture fits in RAM");
        volume
            .write_all_at(0x8001, b"CD001")
            .expect("the magic writes");
        let error =
            analyze(Box::new(volume)).expect_err("a positive probe with no sequence errors");
        let text = error.to_string();
        assert!(text.contains("sector 16"), "{text}");
        assert!(text.contains("version"), "{text}");
    }

    #[test]
    fn analyze_file_opens_an_iso_from_disk() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("fixture.iso");
        std::fs::write(&path, label_fixture_bytes()).expect("the fixture file");
        let report = analyze_file(&path).expect("the file analyses");
        assert_eq!(report.kind, "iso");
        assert_eq!(report.labels.primary.as_deref(), Some("TESTVOL"));
    }

    #[test]
    fn report_serde_round_trip_skips_absent_fields() {
        // serde_json is not a dependency of this crate (PLAN section 5
        // forbids another one), so the round trip goes through toml:
        // absent options and the empty image list must vanish from the
        // output, and the round trip must be equal.
        let report = ImageReport {
            kind: "iso".to_string(),
            is_iso: true,
            windows_version: Some("11".to_string()),
            build: Some(22631),
            wim_images: vec![WimImage {
                index: 1,
                name: Some("Pro".to_string()),
                display_name: None,
                description: None,
            }],
            labels: Labels {
                primary: Some("TESTVOL".to_string()),
                joliet: None,
                udf: None,
            },
            ..ImageReport::default()
        };
        let text = toml::to_string(&report).expect("the report serialises");
        assert!(text.contains("windows_version"), "{text}");
        assert!(!text.contains("grub_version"), "{text}");
        assert!(!text.contains("display_name"), "{text}");
        assert!(!text.contains("joliet"), "{text}");
        let back: ImageReport = toml::from_str(&text).expect("the report round-trips");
        assert_eq!(back, report);
        // The empty image list skips serialising and still parses back.
        let bare = ImageReport {
            kind: "raw".to_string(),
            ..ImageReport::default()
        };
        let text = toml::to_string(&bare).expect("the bare report serialises");
        assert!(!text.contains("wim_images"), "{text}");
        assert!(!text.contains("distro"), "{text}");
        let back: ImageReport = toml::from_str(&text).expect("the bare report round-trips");
        assert_eq!(back, bare);
    }

    #[test]
    fn label_best_prefers_primary_then_joliet_then_udf() {
        let full = Labels {
            primary: Some("P".to_string()),
            joliet: Some("J".to_string()),
            udf: Some("U".to_string()),
        };
        assert_eq!(full.best(), Some("P"));
        let blank_primary = Labels {
            primary: Some(String::new()),
            joliet: Some("J".to_string()),
            udf: Some("U".to_string()),
        };
        assert_eq!(blank_primary.best(), Some("J"));
        let udf_only = Labels {
            udf: Some("U".to_string()),
            ..Labels::default()
        };
        assert_eq!(udf_only.best(), Some("U"));
        assert_eq!(Labels::default().best(), None);
    }
}
