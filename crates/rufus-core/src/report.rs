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
//! Slices 2-6 fill the rest: slice 2 was the WIM reader (the header
//! and XML resource behind [`WimReader`](crate::wim::WimReader)), slice
//! 3 is Windows (this slice: `is_windows`, `windows_version`, `build`,
//! `is_windows_to_go`, `wim_images`), slices 4-5 the distro and
//! persistence fields and the bootloader fields (`has_efi`,
//! `has_bios`, `has_grub`, `has_syslinux` and the versions), and slice
//! 6 the CLI wiring. Every one of those fields exists here already so
//! [`ImageReport`] stays stable across the slices.
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
use crate::wim;

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

/// One Windows edition from a WIM XML: slice 3/6 fills these; the type
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
/// this slice fills the Windows fields; slices 4-6 fill the rest, each
/// documented on its field.
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
    /// True when slice 3/6 proves a Windows payload (path rules over
    /// the tree index plus the WIM contents below).
    pub is_windows: bool,
    /// Windows major version, e.g. `"11"` (slice 3/6 fills this from
    /// the WIM XML).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_version: Option<String>,
    /// Windows build number, e.g. `22631` (slice 3/6 fills this from
    /// the WIM XML).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<u32>,
    /// True for a Windows To Go layout (slice 3/6 fills this).
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
    /// One entry per Windows edition from the WIM XML (slice 3/6 fills
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

/// WinPE/boot image: always present on a Windows install ISO.
const BOOT_WIM: &str = "/sources/boot.wim";

/// The edition payload as a plain WIM.
const INSTALL_WIM: &str = "/sources/install.wim";

/// The edition payload as a solid archive (ESD).
const INSTALL_ESD: &str = "/sources/install.esd";

/// BIOS boot manager at the root.
const BOOTMGR: &str = "/bootmgr";

/// Installer at the root.
const SETUP_EXE: &str = "/setup.exe";

/// XP/2003 era text-mode setup at the root.
const TXTSETUP_SIF: &str = "/txtsetup.sif";

/// XP/2003 era text-mode setup under the 32-bit tree (the decompiled
/// `FUN_14001c640` builds `/%s/txtsetup.sif` from `i386`/`amd64`).
const TXTSETUP_SIF_I386: &str = "/i386/txtsetup.sif";

/// XP/2003 era text-mode setup under the 64-bit tree (see
/// [`TXTSETUP_SIF_I386`]).
const TXTSETUP_SIF_AMD64: &str = "/amd64/txtsetup.sif";

/// A WinPE/minint tree rather than an install tree.
const MININT: &str = "/minint";

/// Earliest build that can host Windows To Go: Windows 8 (see
/// [`classify_windows`]).
const WINDOWS_TO_GO_MIN_BUILD: u32 = 9200;

/// A readable window over a WIM file inside either family: the ISO
/// handle borrows its reader (windows come from
/// [`IsoReader::read_open_at`]), the UDF handle carries the walked
/// entry (windows come from [`UdfReader::read_file_at`], which re-opens
/// per call). The UDF length is read once at construction: [`len`](Self::len)
/// is infallible by contract, and an entry whose length refuses to open
/// is a real error, not a silent zero.
enum WimFile<'a> {
    Iso {
        reader: &'a IsoReader,
        file: crate::iso::OpenFile,
    },
    Udf {
        reader: &'a UdfReader,
        entry: crate::udf::Entry,
        len: u64,
    },
}

impl WimFile<'_> {
    /// File length in bytes.
    fn len(&self) -> u64 {
        match self {
            Self::Iso { file, .. } => u64::from(file.len()),
            Self::Udf { len, .. } => *len,
        }
    }

    /// Fill `buf` completely from `offset`: loops the short-read
    /// `read_open_at`/`read_file_at` APIs and refuses a premature end,
    /// naming the wanted and placed counts. An I/O refusal propagates:
    /// the volume lied about its own bytes.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let wanted = buf.len();
        let mut placed: usize = 0;
        while placed < wanted {
            let at = offset.checked_add(placed as u64).ok_or_else(|| {
                CoreError::invalid(format!(
                    "wim file read at offset {offset} overflows the byte offset arithmetic"
                ))
            })?;
            let dest = buf.get_mut(placed..).ok_or_else(|| {
                CoreError::invalid(format!(
                    "wim file read window {placed}..{wanted} runs past the {wanted} byte buffer"
                ))
            })?;
            let got = match self {
                Self::Iso { reader, file } => reader.read_open_at(file, at, dest)?,
                Self::Udf { reader, entry, .. } => reader.read_file_at(entry, at, dest)?,
            };
            if got == 0 {
                return Err(CoreError::invalid(format!(
                    "wim file read of {wanted} bytes at offset {offset} placed only {placed} \
                     bytes: refusing a short read"
                )));
            }
            placed = placed.checked_add(got).ok_or_else(|| {
                CoreError::invalid("wim file read position overflows the offset arithmetic")
            })?;
        }
        Ok(())
    }
}

/// Read the WIM behind `file`: the 208-byte header at 0, then the XML
/// resource it names.
///
/// An undersized file (fewer than [`HEADER_SIZE`](wim::HEADER_SIZE)
/// bytes) is not a WIM and reads `Ok(None)`; a header that refuses to
/// parse reads `Ok(None)` too, as does an XML extent that fails its
/// range check — a bogus or truncated `boot.wim` degrades the report
/// rather than failing the whole analysis (Rufus warns and continues).
/// The XML range is cap-checked before any read and the buffer is grown
/// with `try_reserve`, mirroring [`WimReader`](wim::WimReader); bytes
/// that are not stored UTF-16 read `Ok(None)` through
/// [`is_stored_xml`](wim::reader::is_stored_xml). An I/O error from
/// [`read_at`](WimFile::read_at) propagates: the volume lied about its
/// own bytes.
fn read_wim(file: &WimFile<'_>) -> Result<Option<wim::WimXml>> {
    if file.len() < u64::from(wim::HEADER_SIZE) {
        return Ok(None);
    }
    let mut header_bytes = [0u8; wim::HEADER_SIZE as usize];
    file.read_at(0, &mut header_bytes)?;
    let header = match wim::WimHeader::parse(&header_bytes) {
        Ok(header) => header,
        Err(_) => return Ok(None),
    };
    // A wrong XML extent is the payload's own metadata being wrong, not
    // I/O: degrade like a bogus header. (The bound below is the file
    // length, not a volume end — the shared range check names a volume
    // because it also serves whole-volume reads.)
    let (offset, size) = match header.checked_xml_range(file.len()) {
        Ok(range) => range,
        Err(_) => return Ok(None),
    };
    let count = usize::try_from(size).map_err(|_| {
        CoreError::invalid(format!(
            "wim xml resource size {size} does not fit this machine's address space"
        ))
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve(count).map_err(|_| {
        CoreError::invalid(format!("wim xml resource size {size} cannot be buffered"))
    })?;
    bytes.resize(count, 0);
    file.read_at(offset, &mut bytes)?;
    if !wim::reader::is_stored_xml(&bytes) {
        return Ok(None);
    }
    Ok(Some(wim::xml::parse(&bytes)))
}

/// Windows classification: the path rules plus whatever the WIM
/// payloads say.
struct WindowsInfo {
    is_windows: bool,
    windows_version: Option<String>,
    build: Option<u32>,
    is_windows_to_go: bool,
    wim_images: Vec<WimImage>,
}

/// The first `<WINDOWS><VERSION>` in `xml`, if any image carries one.
fn first_version(xml: &wim::WimXml) -> Option<wim::WimVersion> {
    xml.images.iter().find_map(|image| image.version)
}

/// Classify Windows from the tree index and the two WIM payloads.
///
/// `is_windows` is true when ANY of these hold, each documented where
/// it is checked: [`BOOT_WIM`], [`INSTALL_WIM`], [`INSTALL_ESD`],
/// [`BOOTMGR`] AND [`SETUP_EXE`] together, any `txtsetup.sif` variant
/// ([`TXTSETUP_SIF`], [`TXTSETUP_SIF_I386`], [`TXTSETUP_SIF_AMD64`]),
/// [`MININT`].
///
/// `windows_version`/`build` come from the WIM XML
/// `<WINDOWS><VERSION><MAJOR>` (as a decimal string) and `<BUILD>` (as
/// `u32`): the decompiled `FUN_140030930` prints `Detected: Windows %d
/// ISO (Build %d.%d)` with `%d` the XML MAJOR and `%d.%d` BUILD.REVISION,
/// and `FUN_140065150` refuses a report with no version info — so a
/// missing VERSION simply leaves both fields empty. The first payload
/// that yields a VERSION wins — `boot.wim` first, then the install
/// payload — so a boot image without a `<WINDOWS>` block (what `wimlib`
/// writes when it captures a plain directory) does not block the
/// install payload's version. Within one payload, the first image
/// carrying a VERSION wins (a WIM's images share one build in
/// practice).
///
/// `wim_images` come from the install payload when it yielded at least
/// one image, else from `boot.wim` when it did, in XML document order
/// with nothing skipped. Each [`ImageXml`](wim::ImageXml) maps to
/// [`WimImage`] field for field; an image with a missing DISPLAYNAME
/// keeps `display_name: None` (slice 2 already records the parser's
/// rule).
///
/// `is_windows_to_go` is `is_windows && build >= 9200 &&
/// !wim_images.is_empty()`: Windows To Go needs Windows 8 (build 9200)
/// or newer plus a WIM payload to deploy (the PLAN gives no rule, so
/// this pins that reasoning). `FUN_1400660c0` shows WTG as choosing one
/// installed image index by DISPLAYNAME (it logs `Will use '%s'
/// (Build: %d, Index %s) for Windows To Go`): the report field answers
/// "could this image be written in Windows To Go mode", not "is this a
/// WTG drive".
///
/// Both payloads are read independently: a parse refusal in one degrades
/// that payload to `None` (see [`read_wim`]) without touching the
/// other. An I/O failure in either propagates.
fn classify_windows(
    index: &TreeIndex,
    boot: Option<&WimFile<'_>>,
    install: Option<&WimFile<'_>>,
) -> Result<WindowsInfo> {
    let has_txtsetup =
        index.has(TXTSETUP_SIF) || index.has(TXTSETUP_SIF_I386) || index.has(TXTSETUP_SIF_AMD64);
    // Each clause of the ANY below, in brief order: the WinPE/boot
    // image, the edition payloads (WIM or solid ESD), the BIOS boot
    // manager together with the installer, any text-mode setup marker,
    // the WinPE/minint tree.
    let is_windows = index.has(BOOT_WIM)
        || index.has(INSTALL_WIM)
        || index.has(INSTALL_ESD)
        || (index.has(BOOTMGR) && index.has(SETUP_EXE))
        || has_txtsetup
        || index.has(MININT);
    let boot_xml = match boot {
        Some(file) => read_wim(file)?,
        None => None,
    };
    let install_xml = match install {
        Some(file) => read_wim(file)?,
        None => None,
    };
    let version = boot_xml
        .as_ref()
        .and_then(first_version)
        .or_else(|| install_xml.as_ref().and_then(first_version));
    let (windows_version, build) = match version {
        Some(found) => (Some(found.major.to_string()), Some(found.build)),
        None => (None, None),
    };
    let edition_source = install_xml
        .as_ref()
        .filter(|xml| !xml.images.is_empty())
        .or(boot_xml.as_ref().filter(|xml| !xml.images.is_empty()));
    let mut wim_images = Vec::new();
    if let Some(xml) = edition_source {
        for image in xml.images.iter() {
            wim_images.push(WimImage {
                index: image.index,
                name: image.name.clone(),
                display_name: image.display_name.clone(),
                description: image.description.clone(),
            });
        }
    }
    let is_windows_to_go = is_windows
        && build.is_some_and(|found| found >= WINDOWS_TO_GO_MIN_BUILD)
        && !wim_images.is_empty();
    Ok(WindowsInfo {
        is_windows,
        windows_version,
        build,
        is_windows_to_go,
        wim_images,
    })
}

/// Open the indexed WIM at `marker` through the ISO reader, when the
/// marker exists: `None` for a missing marker or a directory at the
/// marker (a directory is not a WIM and degrades like a bogus file).
/// The indexed node's own path opens the file, so the exact walked
/// spelling resolves. Any other open failure propagates.
fn open_iso_wim<'a>(
    reader: &'a IsoReader,
    index: &TreeIndex,
    marker: &str,
) -> Result<Option<WimFile<'a>>> {
    let Some(node) = index.get(marker) else {
        return Ok(None);
    };
    if node.is_dir {
        return Ok(None);
    }
    let file = reader.open_file(&node.path)?;
    Ok(Some(WimFile::Iso { reader, file }))
}

/// Open the UDF entry at `marker` from one `walk()` pass, when the
/// marker exists: `None` for a missing marker or a directory at the
/// marker (see [`open_iso_wim`]). The match is ASCII-case-insensitive
/// over the walked absolute paths. The length is read once here so
/// [`WimFile::len`] stays infallible; an entry whose length refuses to
/// open propagates as a real error.
fn open_udf_wim<'a>(
    reader: &'a UdfReader,
    walked: &[(String, crate::udf::Entry)],
    marker: &str,
) -> Result<Option<WimFile<'a>>> {
    let Some((_, entry)) = walked
        .iter()
        .find(|(path, _)| path.eq_ignore_ascii_case(marker))
    else {
        return Ok(None);
    };
    if entry.is_directory {
        return Ok(None);
    }
    let len = reader.open_file(entry).map(|file| file.len())?;
    Ok(Some(WimFile::Udf {
        reader,
        entry: entry.clone(),
        len,
    }))
}

/// Analyse `volume`: probe ISO, then UDF, else report `"raw"`.
///
/// A reader that fails on a volume that probed positive is a real
/// error and is returned (never silently downgraded to `"raw"`).
/// Only ISO and UDF are in scope: a `.wim`, VHD or anything else
/// unrecognised is `"raw"` for now, with every flag false.
///
/// Cost note: the tree index is built, used in place for the Windows
/// rules below, then dropped with the reader, so the return type stays
/// [`ImageReport`]. A UDF volume carrying a WIM marker pays for one
/// extra walk (see the UDF arm); a later slice that needs the index
/// beyond [`analyze`] will return it alongside the report.
pub fn analyze(volume: Box<dyn Volume>) -> Result<ImageReport> {
    if has_iso_magic(volume.as_ref())? {
        let reader = IsoReader::open(volume)?;
        let index = TreeIndex::from_iso(&reader);
        let boot = open_iso_wim(&reader, &index, BOOT_WIM)?;
        // The plain payload wins over the solid one when both mark.
        let install = open_iso_wim(&reader, &index, INSTALL_WIM)?.or(open_iso_wim(
            &reader,
            &index,
            INSTALL_ESD,
        )?);
        let windows = classify_windows(&index, boot.as_ref(), install.as_ref())?;
        return Ok(ImageReport {
            kind: "iso".to_string(),
            is_iso: true,
            is_windows: windows.is_windows,
            windows_version: windows.windows_version,
            build: windows.build,
            is_windows_to_go: windows.is_windows_to_go,
            wim_images: windows.wim_images,
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
        // The index drops the walked entries the WIM handles need, so a
        // UDF volume marked with a WIM path (/sources/boot.wim,
        // /sources/install.wim, /sources/install.esd) pays for one
        // extra walk here; any other volume — including a
        // bootmgr+setup.exe one with no WIM marker — never does.
        let walked = if index.has(BOOT_WIM) || index.has(INSTALL_WIM) || index.has(INSTALL_ESD) {
            Some(reader.walk()?)
        } else {
            None
        };
        let empty: &[(String, crate::udf::Entry)] = &[];
        let walked = walked.as_deref().unwrap_or(empty);
        let boot = open_udf_wim(&reader, walked, BOOT_WIM)?;
        let install = open_udf_wim(&reader, walked, INSTALL_WIM)?.or(open_udf_wim(
            &reader,
            walked,
            INSTALL_ESD,
        )?);
        let windows = classify_windows(&index, boot.as_ref(), install.as_ref())?;
        return Ok(ImageReport {
            kind: "udf".to_string(),
            is_udf: true,
            is_windows: windows.is_windows,
            windows_version: windows.windows_version,
            build: windows.build,
            is_windows_to_go: windows.is_windows_to_go,
            wim_images: windows.wim_images,
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

    /// Encode `text` as UTF-16LE with a `FF FE` BOM, the way real WIM
    /// XML resources are stored (slice 2 measured this).
    fn utf16le_bom(text: &str) -> Vec<u8> {
        let mut out = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    /// Whole WIM file bytes around `xml`: the slice-2 synthetic header
    /// builder with the measured XPRESS flags.
    fn wim_file(xml: &str) -> Vec<u8> {
        crate::wim::header::wim_bytes(&utf16le_bom(xml), 0x20082)
    }

    /// Primary-only ISO with one subdirectory: the root at sector 20
    /// holds `dir_name` (at sector 21) plus one record per
    /// `(identifier, sector, bytes)` in `root_files`; the subdirectory
    /// holds one record per entry in `sub_files`. Each file's bytes go
    /// to its sector. Identifiers carry the `;1` version suffix, as
    /// real mastering tools write them.
    fn one_dir_iso(
        dir_name: &[u8],
        root_files: &[(&[u8], u32, &[u8])],
        sub_files: &[(&[u8], u32, &[u8])],
    ) -> Vec<u8> {
        const DIR_SECTOR: u32 = 21;
        let mut root = vec![
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(DIR_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, dir_name),
        ];
        let mut writes: Vec<(u32, Vec<u8>)> = vec![
            (
                16,
                primary_sector("TESTVOL", ROOT_SECTOR, SECTOR_BYTES as u32).to_vec(),
            ),
            (17, terminator_sector().to_vec()),
        ];
        for (identifier, sector, bytes) in root_files {
            root.push(encode_record(*sector, bytes.len() as u32, 0, identifier));
            writes.push((*sector, bytes.to_vec()));
        }
        writes.push((ROOT_SECTOR, dir_sector(&root).to_vec()));
        let mut sub = vec![
            encode_record(DIR_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        ];
        for (identifier, sector, bytes) in sub_files {
            sub.push(encode_record(*sector, bytes.len() as u32, 0, identifier));
            writes.push((*sector, bytes.to_vec()));
        }
        writes.push((DIR_SECTOR, dir_sector(&sub).to_vec()));
        image_with(&writes)
    }

    /// Boot WIM XML: one image, build 19041.
    const BOOT_XML_19041: &str = "<WIM><TOTALBYTES>1</TOTALBYTES><IMAGE INDEX=\"1\"><NAME>Windows 10 Pro</NAME><DISPLAYNAME>Windows 10 Pro</DISPLAYNAME><WINDOWS><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>19041</BUILD><REVISION>1</REVISION></VERSION></WINDOWS></IMAGE></WIM>";

    /// Install WIM XML: two images, builds 19041.
    const INSTALL_XML_TWO: &str = "<WIM><TOTALBYTES>2</TOTALBYTES><IMAGE INDEX=\"1\"><NAME>Windows 10 Pro</NAME><DISPLAYNAME>Windows 10 Pro</DISPLAYNAME><WINDOWS><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>19041</BUILD></VERSION></WINDOWS></IMAGE><IMAGE INDEX=\"2\"><NAME>Windows 10 Home</NAME><DISPLAYNAME>Windows 10 Home</DISPLAYNAME><WINDOWS><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>19041</BUILD></VERSION></WINDOWS></IMAGE></WIM>";

    /// Boot WIM XML: one image, build 7601 (Windows 7, pre-Windows To Go).
    const BOOT_XML_7601: &str = "<WIM><TOTALBYTES>1</TOTALBYTES><IMAGE INDEX=\"1\"><NAME>Windows 7 Ultimate</NAME><DISPLAYNAME>Windows 7 Ultimate</DISPLAYNAME><WINDOWS><VERSION><MAJOR>6</MAJOR><MINOR>1</MINOR><BUILD>7601</BUILD></VERSION></WINDOWS></IMAGE></WIM>";

    /// Install WIM XML: one image, build 7601.
    const INSTALL_XML_7601: &str = "<WIM><TOTALBYTES>1</TOTALBYTES><IMAGE INDEX=\"1\"><NAME>Windows 7 Ultimate</NAME><DISPLAYNAME>Windows 7 Ultimate</DISPLAYNAME><WINDOWS><VERSION><MAJOR>6</MAJOR><MINOR>1</MINOR><BUILD>7601</BUILD></VERSION></WINDOWS></IMAGE></WIM>";

    /// Boot WIM XML with no `<WINDOWS>` block: what `wimlib` writes
    /// when it captures a plain directory, and what a repacked boot.wim
    /// looks like.
    const BOOT_XML_NO_WINDOWS: &str = "<WIM><TOTALBYTES>1</TOTALBYTES><IMAGE INDEX=\"1\"><NAME>Boot image</NAME><DISPLAYNAME>Boot image</DISPLAYNAME></IMAGE></WIM>";

    /// Install WIM XML: two images, build 22631.
    const INSTALL_XML_22631: &str = "<WIM><TOTALBYTES>2</TOTALBYTES><IMAGE INDEX=\"1\"><NAME>Windows 11 Pro</NAME><DISPLAYNAME>Windows 11 Pro</DISPLAYNAME><WINDOWS><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>22631</BUILD></VERSION></WINDOWS></IMAGE><IMAGE INDEX=\"2\"><NAME>Windows 11 Home</NAME><DISPLAYNAME>Windows 11 Home</DISPLAYNAME><WINDOWS><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>22631</BUILD></VERSION></WINDOWS></IMAGE></WIM>";

    /// Install WIM XML with no images: parses cleanly but yields no
    /// editions.
    const INSTALL_XML_EMPTY: &str = "<WIM><TOTALBYTES>0</TOTALBYTES></WIM>";

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

    #[test]
    fn windows_iso_reports_version_build_and_editions() {
        let boot = wim_file(BOOT_XML_19041);
        let install = wim_file(INSTALL_XML_TWO);
        let iso = one_dir_iso(
            b"SOURCES",
            &[],
            &[
                (b"BOOT.WIM;1".as_slice(), BOOT_WIM_SECTOR, boot.as_slice()),
                (b"INSTALL.WIM;1".as_slice(), 23, install.as_slice()),
            ],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert_eq!(report.kind, "iso");
        assert!(report.is_iso);
        assert!(!report.is_udf);
        assert!(report.is_windows);
        assert_eq!(report.windows_version.as_deref(), Some("10"));
        assert_eq!(report.build, Some(19041));
        assert_eq!(report.wim_images.len(), 2);
        assert_eq!(
            report.wim_images[0].display_name.as_deref(),
            Some("Windows 10 Pro")
        );
        assert_eq!(
            report.wim_images[1].display_name.as_deref(),
            Some("Windows 10 Home")
        );
        assert!(report.is_windows_to_go);
    }

    #[test]
    fn bootmgr_and_setup_alone_make_a_windows_image() {
        let iso = one_dir_iso(
            b"SOURCES",
            &[
                (b"BOOTMGR;1".as_slice(), 22, b"boot".as_slice()),
                (b"SETUP.EXE;1".as_slice(), 23, b"setup".as_slice()),
            ],
            &[],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(report.is_windows);
        assert_eq!(report.windows_version, None);
        assert_eq!(report.build, None);
        assert!(report.wim_images.is_empty());
        assert!(!report.is_windows_to_go);
    }

    #[test]
    fn txtsetup_sif_marks_an_xp_image() {
        // Uppercase spelling: the marker lookup is case-insensitive.
        let iso = one_dir_iso(
            b"I386",
            &[],
            &[(b"TXTSETUP.SIF;1".as_slice(), 22, b"[data]".as_slice())],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(report.is_windows);
        assert_eq!(report.windows_version, None);
        assert_eq!(report.build, None);
        assert!(report.wim_images.is_empty());
    }

    #[test]
    fn a_plain_iso_is_not_windows() {
        let iso = image_with(&[
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
                    encode_record(22, 9, 0, b"README.TXT;1"),
                ])
                .to_vec(),
            ),
            (22, b"plain txt".to_vec()),
        ]);
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert_eq!(report.kind, "iso");
        assert!(!report.is_windows);
        assert_eq!(report.windows_version, None);
        assert_eq!(report.build, None);
        assert!(!report.is_windows_to_go);
        assert!(report.wim_images.is_empty());
        let text = toml::to_string(&report).expect("the report serialises");
        assert!(!text.contains("wim_images"), "{text}");
    }

    #[test]
    fn old_build_is_not_windows_to_go() {
        let boot = wim_file(BOOT_XML_7601);
        let install = wim_file(INSTALL_XML_7601);
        let iso = one_dir_iso(
            b"SOURCES",
            &[],
            &[
                (b"BOOT.WIM;1".as_slice(), BOOT_WIM_SECTOR, boot.as_slice()),
                (b"INSTALL.WIM;1".as_slice(), 23, install.as_slice()),
            ],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(report.is_windows);
        assert_eq!(report.windows_version.as_deref(), Some("6"));
        assert_eq!(report.build, Some(7601));
        assert_eq!(report.wim_images.len(), 1);
        assert!(!report.is_windows_to_go);
    }

    #[test]
    fn bootmgr_alone_is_not_windows() {
        let iso = one_dir_iso(
            b"SOURCES",
            &[(b"BOOTMGR;1".as_slice(), 22, b"boot".as_slice())],
            &[],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(!report.is_windows);
        assert_eq!(report.windows_version, None);
        assert_eq!(report.build, None);
    }

    #[test]
    fn corrupt_boot_wim_degrades_without_error() {
        // Right path, 40 bytes of garbage: the marker still proves a
        // Windows payload, but no version or edition can come out of it.
        let garbage = vec![0xABu8; 40];
        let iso = one_dir_iso(
            b"SOURCES",
            &[],
            &[(
                b"BOOT.WIM;1".as_slice(),
                BOOT_WIM_SECTOR,
                garbage.as_slice(),
            )],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("a bogus WIM never errors");
        assert!(report.is_windows);
        assert_eq!(report.windows_version, None);
        assert_eq!(report.build, None);
        assert!(report.wim_images.is_empty());
        assert!(!report.is_windows_to_go);
    }

    #[test]
    fn version_falls_back_to_install_when_boot_is_corrupt() {
        let garbage = vec![0xABu8; 40];
        let install = wim_file(INSTALL_XML_TWO);
        let iso = one_dir_iso(
            b"SOURCES",
            &[],
            &[
                (
                    b"BOOT.WIM;1".as_slice(),
                    BOOT_WIM_SECTOR,
                    garbage.as_slice(),
                ),
                (b"INSTALL.WIM;1".as_slice(), 23, install.as_slice()),
            ],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(report.is_windows);
        assert_eq!(report.windows_version.as_deref(), Some("10"));
        assert_eq!(report.build, Some(19041));
        assert_eq!(report.wim_images.len(), 2);
        assert!(report.is_windows_to_go);
    }

    #[test]
    fn wim_file_read_at_fills_exactly_and_names_short_reads() {
        let reader = IsoReader::open(Box::new(memory_volume(&tree_fixture_bytes())))
            .expect("the fixture opens");
        let file = reader
            .open_file("SOURCES/BOOT.WIM")
            .expect("the file opens");
        let wim = WimFile::Iso {
            reader: &reader,
            file,
        };
        assert_eq!(wim.len(), 12);
        // The happy path: an exact fill returns the file bytes.
        let mut exact = vec![0u8; 12];
        wim.read_at(0, &mut exact).expect("the exact read fills");
        assert_eq!(exact, b"wim-content!");
        // Past the file end the refusal names the wanted and placed
        // counts (10 wanted, 2 placed).
        let mut short = vec![0u8; 10];
        let error = wim
            .read_at(10, &mut short)
            .expect_err("a short read refuses");
        let text = error.to_string();
        assert!(text.contains("10"), "{text}");
        assert!(text.contains('2'), "{text}");
    }

    #[test]
    fn truncated_boot_wim_degrades_without_error() {
        // Header intact, XML extent cut short: the file holds the first
        // 300 bytes of a WIM whose XML runs past that, so the range
        // check refuses and the report degrades instead of erroring.
        let full = wim_file(BOOT_XML_19041);
        assert!(
            full.len() > 300,
            "the fixture must actually truncate the XML extent"
        );
        let cut = full[..300].to_vec();
        let iso = one_dir_iso(
            b"SOURCES",
            &[],
            &[(b"BOOT.WIM;1".as_slice(), BOOT_WIM_SECTOR, cut.as_slice())],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("a truncated WIM never errors");
        assert_eq!(report.kind, "iso");
        assert!(report.is_windows);
        assert_eq!(report.windows_version, None);
        assert_eq!(report.build, None);
        assert!(report.wim_images.is_empty());
        assert!(!report.is_windows_to_go);
    }

    #[test]
    fn version_falls_back_to_install_when_boot_has_no_windows_block() {
        // boot.wim parses cleanly but carries no VERSION (what wimlib
        // writes for a plain directory capture): the version, build and
        // Windows To Go answer come from install.wim instead.
        let boot = wim_file(BOOT_XML_NO_WINDOWS);
        let install = wim_file(INSTALL_XML_22631);
        let iso = one_dir_iso(
            b"SOURCES",
            &[],
            &[
                (b"BOOT.WIM;1".as_slice(), BOOT_WIM_SECTOR, boot.as_slice()),
                (b"INSTALL.WIM;1".as_slice(), 23, install.as_slice()),
            ],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(report.is_windows);
        assert_eq!(report.windows_version.as_deref(), Some("10"));
        assert_eq!(report.build, Some(22631));
        assert!(report.is_windows_to_go);
        assert_eq!(report.wim_images.len(), 2);
        assert_eq!(
            report.wim_images[0].display_name.as_deref(),
            Some("Windows 11 Pro")
        );
        assert_eq!(
            report.wim_images[1].display_name.as_deref(),
            Some("Windows 11 Home")
        );
    }

    #[test]
    fn editions_fall_back_to_boot_when_install_is_empty() {
        // install.wim parses cleanly but yields no images: the editions
        // come from boot.wim instead of vanishing.
        let boot = wim_file(BOOT_XML_19041);
        let install = wim_file(INSTALL_XML_EMPTY);
        let iso = one_dir_iso(
            b"SOURCES",
            &[],
            &[
                (b"BOOT.WIM;1".as_slice(), BOOT_WIM_SECTOR, boot.as_slice()),
                (b"INSTALL.WIM;1".as_slice(), 23, install.as_slice()),
            ],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(report.is_windows);
        assert_eq!(report.windows_version.as_deref(), Some("10"));
        assert_eq!(report.build, Some(19041));
        assert_eq!(report.wim_images.len(), 1);
        assert_eq!(
            report.wim_images[0].display_name.as_deref(),
            Some("Windows 10 Pro")
        );
    }
}
