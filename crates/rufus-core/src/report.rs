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
//! 3 was Windows (`is_windows`, `windows_version`, `build`,
//! `is_windows_to_go`, `wim_images`), slice 4 the Linux
//! distro/persistence classification (`distro`, `persistence`), slice 5
//! is boot capability (this slice: `has_efi`, `has_bios`, `has_grub`,
//! `grub_version`, `has_syslinux`, `syslinux_version`, plus the
//! [`BootMode`] recommendation), and slice 6 the CLI wiring. Every one
//! of those fields exists here already so [`ImageReport`] stays stable
//! across the slices.
//!
//! [`ImageReport`] carries no `dd_mode` field: the DD-mode rule behind
//! [`forces_dd`](crate::distro::forces_dd) stays a free function until
//! the CLI/write slices decide where to surface it.
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
use crate::iso::BootCatalog;
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
    /// Linux distribution identifier, e.g. `"Ubuntu 24.04.1 LTS
    /// \"Noble Numbat\""` (slice 4/6 fills this: label table first,
    /// then `.disk/info`, then `README.diskdefines`).
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

/// The boot recommendation the PLAN asks to "expose to the plan":
/// which firmware families the image can boot. Computed from
/// [`has_bios`](ImageReport::has_bios)/[`has_efi`](ImageReport::has_efi),
/// so [`ImageReport`]'s field list stays fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// Neither BIOS nor UEFI boot paths were seen.
    None,
    /// BIOS only.
    Bios,
    /// UEFI only.
    Uefi,
    /// Both families: a dual BIOS/UEFI image.
    Both,
}

impl ImageReport {
    /// The boot recommendation from `has_bios`/`has_efi`.
    #[must_use]
    pub fn boot_mode(&self) -> BootMode {
        match (self.has_bios, self.has_efi) {
            (true, true) => BootMode::Both,
            (true, false) => BootMode::Bios,
            (false, true) => BootMode::Uefi,
            (false, false) => BootMode::None,
        }
    }
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

/// KolibriOS image marker (`0x140017f40.c` sets `KolibriOS` for a root
/// `kolibri.img` and logs `Uses: KolibriOS`).
const KOLIBRI_IMG: &str = "/kolibri.img";

/// ReactOS setup loader (`0x140017f40.c` reads the ReactOS flag from a
/// directory holding `setupldr.sys` or `freeldr.sys` and logs
/// `Uses: ReactOS`).
const SETUPLDR_SYS: &str = "/setupldr.sys";

/// ReactOS free loader (see [`SETUPLDR_SYS`]).
const FREELDR_SYS: &str = "/freeldr.sys";

/// FreeDOS kernel: with [`FDCONFIG_SYS`] below it marks a FreeDOS
/// image. FreeDOS and MS-DOS are Rufus *extraction sources*
/// (`0x1400150c0.c`, `0x140014650.c`), not image properties Rufus
/// itself reports, so these two rules are ours and say so.
const KERNEL_SYS: &str = "/kernel.sys";

/// FreeDOS config (see [`KERNEL_SYS`]).
const FDCONFIG_SYS: &str = "/fdconfig.sys";

/// MS-DOS I/O system: with [`MSDOS_SYS`] below it marks an MS-DOS
/// image (see [`KERNEL_SYS`] for the extraction-source note).
const IO_SYS: &str = "/io.sys";

/// MS-DOS system file (see [`IO_SYS`]).
const MSDOS_SYS: &str = "/msdos.sys";

/// Ubuntu-style release metadata: the first non-empty line names the
/// image.
const DISK_INFO: &str = "/.disk/info";

/// Debian-style release metadata: the `#define DISKNAME` value names
/// the image.
const README_DISKDEFINES: &str = "/README.diskdefines";

/// Ubuntu persistence tree: a directory here (or its kernel below)
/// means the `casper` family.
const CASPER_DIR: &str = "/casper";

/// Ubuntu persistence kernel.
const CASPER_KERNEL: &str = "/casper/vmlinuz";

/// Debian-live persistence payload.
const LIVE_SQUASHFS: &str = "/live/filesystem.squashfs";

/// Debian-live persistence kernel.
const LIVE_KERNEL: &str = "/live/vmlinuz";

/// Syslinux boot config, grepped for the persistence kernel options.
const ISOLINUX_CFG: &str = "/isolinux/isolinux.cfg";

/// GRUB boot config, grepped for the persistence kernel options.
const GRUB_CFG: &str = "/boot/grub/grub.cfg";

/// Cap on distro/config text reads in bytes: these files are a few
/// hundred bytes, so anything larger is not one of ours and reads
/// `Ok(None)` rather than making the report allocate.
const MAX_TEXT_BYTES: u64 = 64 * 1024;

/// Cap on bootloader binary scans in bytes (1 MiB): a scanned file
/// larger than this is skipped (`Ok(None)`), so a hostile image cannot
/// make the report allocate a crafted multi-GiB `isolinux.bin`. Reads
/// go through the index's size first — never read then discard.
const MAX_BINARY_SCAN: u64 = 1024 * 1024;

/// Cap on a banner-scan version take in characters: real versions are a
/// handful (`6.04-pre1`, `2.06`), so a longer run is hostile input and
/// is cut rather than carried into the report.
const MAX_VERSION_CHARS: usize = 64;

/// El Torito platform id for 80x86 BIOS boot entries.
const PLATFORM_BIOS: u8 = 0x00;

/// El Torito platform id for EFI boot entries.
const PLATFORM_EFI: u8 = 0xEF;

/// Syslinux/Isolinux presence markers (see [`classify_boot`]).
const SYSLINUX_MARKERS: &[&str] = &[
    "/isolinux/isolinux.bin",
    "/isolinux/isolinux.cfg",
    "/isolinux/ldlinux.c32",
    "/boot/isolinux/isolinux.bin",
    "/boot/isolinux/isolinux.cfg",
    "/syslinux/syslinux.cfg",
    "/boot/syslinux/syslinux.cfg",
    "/isolinux/vesamenu.c32",
];

/// The `ldlinux.c32` probe behind the embedded-version fallback: `6.04`
/// ships with it, `4.07` without (see [`classify_boot`]).
const LDLINUX_C32: &str = "/isolinux/ldlinux.c32";

/// Syslinux version-scan binaries in path order: the first present file
/// whose banner parses wins (see [`classify_boot`]).
const SYSLINUX_BINS: &[&str] = &[
    "/isolinux/isolinux.bin",
    "/boot/isolinux/isolinux.bin",
    "/syslinux/syslinux.bin",
    "/boot/syslinux/syslinux.bin",
];

/// GRUB presence markers (see [`classify_boot`]).
const GRUB_MARKERS: &[&str] = &[
    "/boot/grub/grub.cfg",
    "/boot/grub2/grub.cfg",
    "/grub/grub.cfg",
    "/boot/grub/i386-pc/normal.mod",
    "/boot/grub2/i386-pc/normal.mod",
];

/// GRUB version-scan binaries in path order: the per-architecture
/// `normal.mod` files first, then the core images (see
/// [`classify_boot`]).
const GRUB_BINS: &[&str] = &[
    "/boot/grub/x86_64-efi/normal.mod",
    "/boot/grub/i386-pc/normal.mod",
    "/boot/grub2/x86_64-efi/normal.mod",
    "/boot/grub/core.img",
    "/boot/grub2/core.img",
];

/// EFI file fallback for [`classify_boot`]: with no usable catalog
/// entry, any of these in the index proves a UEFI boot path.
const EFI_FILES: &[&str] = &[
    "/efi/boot/bootx64.efi",
    "/efi/boot/bootia32.efi",
    "/efi/boot/bootaa64.efi",
    "/efi.img",
    "/efiboot.img",
    "/boot/efi.img",
];

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

/// A readable small text file inside either family, reusing the shape
/// of [`WimFile`]: the ISO handle carries the indexed path (opened with
/// [`IsoReader::read_file`]), the UDF handle carries the walked entry
/// (opened with [`UdfReader::read_file`], which re-opens per call).
/// Both sides carry the size so [`read_text`] can refuse an oversized
/// file before buffering it.
enum TextFile<'a> {
    Iso {
        reader: &'a IsoReader,
        path: String,
        size: u64,
    },
    Udf {
        reader: &'a UdfReader,
        entry: crate::udf::Entry,
        size: u64,
    },
}

/// Read the whole text file, decoded as UTF-8 lossily with a BOM
/// stripped and trailing whitespace/newlines trimmed; the caller takes
/// whatever lines it needs. Refuse nothing: an oversized file is
/// `Ok(None)` (see [`MAX_TEXT_BYTES`]), and an unreadable file is
/// `Ok(None)` too. A raw I/O error ([`CoreError::Io`](crate::CoreError))
/// propagates — on ISO the readers let storage errors through
/// unwrapped, while on UDF the reader wraps every refusal with file
/// context, so there every read refusal degrades instead.
fn read_text(file: &TextFile<'_>) -> Result<Option<String>> {
    let size = match file {
        TextFile::Iso { size, .. } => *size,
        TextFile::Udf { size, .. } => *size,
    };
    if size > MAX_TEXT_BYTES {
        return Ok(None);
    }
    let bytes = match file {
        TextFile::Iso { reader, path, .. } => match reader.read_file(path) {
            Ok(bytes) => bytes,
            Err(error @ CoreError::Io { .. }) => return Err(error),
            Err(_) => return Ok(None),
        },
        TextFile::Udf { reader, entry, .. } => match reader.read_file(entry) {
            Ok(bytes) => bytes,
            Err(error @ CoreError::Io { .. }) => return Err(error),
            Err(_) => return Ok(None),
        },
    };
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    let stripped = text.strip_prefix('\u{FEFF}').map(str::to_string);
    if let Some(clean) = stripped {
        text = clean;
    }
    Ok(Some(text.trim_end().to_string()))
}

/// Cut a trailing ` - ` metadata segment: at the last ` - `, keeping
/// the longest name when several appear.
fn cut_trailing_dash(text: &str) -> &str {
    match text.rfind(" - ") {
        Some(at) => match text.get(..at) {
            Some(head) => head.trim_end(),
            None => text,
        },
        None => text,
    }
}

/// Cut a trailing parenthesised segment (`(20240827)`): only when the
/// trimmed line ends with `)` and holds a matching `(`.
fn cut_trailing_paren(text: &str) -> &str {
    let trimmed = text.trim_end();
    if !trimmed.ends_with(')') {
        return trimmed;
    }
    match trimmed.rfind('(') {
        Some(at) => match trimmed.get(..at) {
            Some(head) => head.trim_end(),
            None => trimmed,
        },
        None => trimmed,
    }
}

/// Strip one pair of surrounding double quotes, if both are there.
fn strip_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && bytes.first() == Some(&b'"') && bytes.last() == Some(&b'"') {
        match value.get(1..bytes.len().saturating_sub(1)) {
            Some(inner) => inner,
            None => value,
        }
    } else {
        value
    }
}

/// Parse `.disk/info` text: the first non-empty trimmed line, minus a
/// trailing ` - ` segment, minus a trailing parenthesised date segment
/// if any (`Ubuntu 24.04.1 LTS "Noble Numbat" - Release amd64
/// (20240827)` becomes `Ubuntu 24.04.1 LTS "Noble Numbat"`).
fn parse_disk_info(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let name = cut_trailing_paren(cut_trailing_dash(line));
        if name.is_empty() {
            continue;
        }
        return Some(name.to_string());
    }
    None
}

/// Parse `README.diskdefines` text: the `#define DISKNAME` value (after
/// one or more spaces), with surrounding double quotes stripped, then
/// the same ` - ` cut as [`.disk/info`](parse_disk_info). Only a line
/// starting with `#define` (past leading whitespace) counts, and only
/// the exact `DISKNAME` key; values may contain `//` or `#` inside
/// quotes — comments are never stripped mid-value. An empty value keeps
/// scanning later lines.
fn parse_diskdefines(text: &str) -> Option<String> {
    for line in text.lines() {
        let after = match line.trim_start().strip_prefix("#define") {
            Some(after) => after,
            None => continue,
        };
        // Exactly the preprocessor shape: whitespace, key, whitespace,
        // value — so `#defineDISKNAME` never matches.
        if !after.starts_with([' ', '\t']) {
            continue;
        }
        let mut words = after.split_ascii_whitespace();
        let key = match words.next() {
            Some(key) => key,
            None => continue,
        };
        if key != "DISKNAME" {
            continue;
        }
        let at = match after.find(key) {
            Some(at) => at.saturating_add(key.len()),
            None => continue,
        };
        let raw = match after.get(at..) {
            Some(rest) => rest.trim_start(),
            None => continue,
        };
        if raw.is_empty() {
            continue;
        }
        let value = cut_trailing_dash(strip_quotes(raw));
        if value.is_empty() {
            continue;
        }
        return Some(value.to_string());
    }
    None
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

/// Classify the distro name from the tree markers, the volume label
/// and the release metadata files. Precedence, highest first:
///
/// 0. the DOS-family markers — [`KOLIBRI_IMG`] is `KolibriOS`,
///    [`SETUPLDR_SYS`] or [`FREELDR_SYS`] is `ReactOS` (both per
///    `0x140017f40.c`), [`KERNEL_SYS`] with [`FDCONFIG_SYS`] is
///    `FreeDOS`, [`IO_SYS`] with [`MSDOS_SYS`] is `MS-DOS` (both pairs
///    ours: Rufus uses those files as extraction sources, never as
///    reported image properties). A volume carrying several markers
///    resolves in that order, so the answer is deterministic.
///    (`grldr` and `.miso` are detected by Rufus too but have no field
///    here — `.miso` only forces DD mode — so those markers stay
///    deliberately unread.)
/// 1. a [`DistroTable`](crate::distro::DistroTable) rule matching the
///    label — the faithful port of `0x140031220.c`, checked against
///    [`best`](Labels::best()), else the UDF label;
/// 2. the parsed [`.disk/info`](parse_disk_info) name;
/// 3. the parsed [`README.diskdefines`](parse_diskdefines) name.
///
/// Steps 2-3 are this project's addition: Rufus's report has no distro
/// name at all.
fn classify_distro(
    index: &TreeIndex,
    labels: &Labels,
    disk_info: Option<&str>,
    diskdefines: Option<&str>,
) -> Option<String> {
    if index.has(KOLIBRI_IMG) {
        return Some("KolibriOS".to_string());
    }
    if index.has(SETUPLDR_SYS) || index.has(FREELDR_SYS) {
        return Some("ReactOS".to_string());
    }
    if index.has(KERNEL_SYS) && index.has(FDCONFIG_SYS) {
        return Some("FreeDOS".to_string());
    }
    if index.has(IO_SYS) && index.has(MSDOS_SYS) {
        return Some("MS-DOS".to_string());
    }
    if let Some(label) = labels.best().or(labels.udf.as_deref())
        && let Some(rule) = crate::distro::DistroTable::embedded().match_label(label)
    {
        return Some(rule.distro.clone());
    }
    if let Some(name) = disk_info.and_then(parse_disk_info) {
        return Some(name);
    }
    if let Some(name) = diskdefines.and_then(parse_diskdefines) {
        return Some(name);
    }
    None
}

/// Classify the persistence method family (`Some("casper")` or
/// `Some("live")`), not the write-time option:
///
/// * `"casper"` when the index holds [`CASPER_DIR`] as a directory or
///   [`CASPER_KERNEL`], or when either boot config text contains
///   `boot=casper` (per `0x1400190e0.c`, `boot=casper` later gains the
///   `persistent` option, with `/casper/vmlinuz` as the fallback path
///   probe);
/// * `"live"` when it holds [`LIVE_SQUASHFS`] or [`LIVE_KERNEL`], or
///   when either boot config text contains `boot=live` (which later
///   gains `persistence`);
/// * casper wins when both appear (Ubuntu carries both trees);
///   `None` otherwise.
///
/// The config texts are only consulted when the caller read them, which
/// happens solely past the marker gate (see the `analyze` arms): no
/// image pays for config reads without a persistence tree. The write
/// slices will append `persistent`/`persistence` per `0x1400190e0.c`;
/// this field only names the family.
fn classify_persistence(
    index: &TreeIndex,
    isolinux_cfg: Option<&str>,
    grub_cfg: Option<&str>,
) -> Option<String> {
    let casper_tree =
        index.get(CASPER_DIR).is_some_and(|node| node.is_dir) || index.has(CASPER_KERNEL);
    let casper_option = isolinux_cfg.is_some_and(|text| text.contains("boot=casper"))
        || grub_cfg.is_some_and(|text| text.contains("boot=casper"));
    if casper_tree || casper_option {
        return Some("casper".to_string());
    }
    let live_tree = index.has(LIVE_SQUASHFS) || index.has(LIVE_KERNEL);
    let live_option = isolinux_cfg.is_some_and(|text| text.contains("boot=live"))
        || grub_cfg.is_some_and(|text| text.contains("boot=live"));
    if live_tree || live_option {
        return Some("live".to_string());
    }
    None
}

/// Open the indexed text file at `marker` through the ISO reader, when
/// the marker exists: `None` for a missing marker, a directory at the
/// marker, or a file whose length is unknown. The indexed node's own
/// path opens the file, so the exact walked spelling resolves.
fn open_text_iso<'a>(
    reader: &'a IsoReader,
    index: &TreeIndex,
    marker: &str,
) -> Option<TextFile<'a>> {
    let node = index.get(marker)?;
    if node.is_dir {
        return None;
    }
    let size = node.size?;
    Some(TextFile::Iso {
        reader,
        path: node.path.clone(),
        size,
    })
}

/// Open the UDF entry at `marker` from one `walk()` pass, when the
/// marker exists: `None` for a missing marker, a directory at the
/// marker, or an entry whose length refuses to open. The match is
/// ASCII-case-insensitive over the walked absolute paths.
fn open_text_udf<'a>(
    reader: &'a UdfReader,
    walked: &[(String, crate::udf::Entry)],
    marker: &str,
) -> Option<TextFile<'a>> {
    let (_, entry) = walked
        .iter()
        .find(|(path, _)| path.eq_ignore_ascii_case(marker))?;
    if entry.is_directory {
        return None;
    }
    let size = reader.open_file(entry).map(|file| file.len()).ok()?;
    Some(TextFile::Udf {
        reader,
        entry: entry.clone(),
        size,
    })
}

/// Read the text file at `marker` through the ISO reader (`Ok(None)`
/// when absent); see [`read_text`] for the cap and error contract.
fn read_iso_text(reader: &IsoReader, index: &TreeIndex, marker: &str) -> Result<Option<String>> {
    match open_text_iso(reader, index, marker) {
        Some(file) => read_text(&file),
        None => Ok(None),
    }
}

/// Read the text file at `marker` from one UDF `walk()` pass
/// (`Ok(None)` when absent); see [`read_text`] for the cap and error
/// contract.
fn read_udf_text(
    reader: &UdfReader,
    walked: &[(String, crate::udf::Entry)],
    marker: &str,
) -> Result<Option<String>> {
    match open_text_udf(reader, walked, marker) {
        Some(file) => read_text(&file),
        None => Ok(None),
    }
}

/// A readable bootloader binary inside either family, in the shape of
/// the existing [`WimFile`]/[`TextFile`] enums: the ISO handle carries
/// the indexed path, the UDF handle carries the walked entry. The open
/// helpers refuse directories, unknown lengths and files larger than
/// [`MAX_BINARY_SCAN`] up front (see [`MAX_BINARY_SCAN`]), so by the
/// time [`read_bin`] buffers, the read is already known small.
enum BinFile<'a> {
    Iso {
        reader: &'a IsoReader,
        path: String,
    },
    Udf {
        reader: &'a UdfReader,
        entry: crate::udf::Entry,
    },
}

/// Open the indexed binary at `marker` through the ISO reader, when the
/// marker exists: `None` for a missing marker, a directory at the
/// marker, a file whose length is unknown, or a file larger than
/// [`MAX_BINARY_SCAN`]. The indexed node's own path opens the file, so
/// the exact walked spelling resolves.
fn open_bin_iso<'a>(reader: &'a IsoReader, index: &TreeIndex, marker: &str) -> Option<BinFile<'a>> {
    let node = index.get(marker)?;
    if node.is_dir {
        return None;
    }
    let size = node.size?;
    if size > MAX_BINARY_SCAN {
        return None;
    }
    Some(BinFile::Iso {
        reader,
        path: node.path.clone(),
    })
}

/// Open the UDF entry at `marker` from one `walk()` pass, when the
/// marker exists: `None` for a missing marker, a directory at the
/// marker, an entry whose length refuses to open, or a file larger than
/// [`MAX_BINARY_SCAN`]. The match is ASCII-case-insensitive over the
/// walked absolute paths.
fn open_bin_udf<'a>(
    reader: &'a UdfReader,
    walked: &[(String, crate::udf::Entry)],
    marker: &str,
) -> Option<BinFile<'a>> {
    let (_, entry) = walked
        .iter()
        .find(|(path, _)| path.eq_ignore_ascii_case(marker))?;
    if entry.is_directory {
        return None;
    }
    let size = reader.open_file(entry).map(|file| file.len()).ok()?;
    if size > MAX_BINARY_SCAN {
        return None;
    }
    Some(BinFile::Udf {
        reader,
        entry: entry.clone(),
    })
}

/// Read the whole binary: version probes are opportunistic, so an
/// unreadable file degrades to `Ok(None)` while a raw I/O error
/// ([`CoreError::Io`](crate::CoreError)) propagates, exactly like
/// [`read_text`].
fn read_bin(file: &BinFile<'_>) -> Result<Option<Vec<u8>>> {
    match file {
        BinFile::Iso { reader, path, .. } => match reader.read_file(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error @ CoreError::Io { .. }) => Err(error),
            Err(_) => Ok(None),
        },
        BinFile::Udf { reader, entry, .. } => match reader.read_file(entry) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error @ CoreError::Io { .. }) => Err(error),
            Err(_) => Ok(None),
        },
    }
}

/// First index of `needle` in `bytes` at or after `from`, if any.
fn find_sub(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let mut at = from;
    while at < bytes.len() {
        let mut hits = true;
        for (offset, &want) in needle.iter().enumerate() {
            if bytes.get(at.saturating_add(offset)) != Some(&want) {
                hits = false;
                break;
            }
        }
        if hits {
            return Some(at);
        }
        at = at.saturating_add(1);
    }
    None
}

/// True when `bytes` holds `needle` at `at`.
fn starts_with_at(bytes: &[u8], at: usize, needle: &[u8]) -> bool {
    match bytes.get(at..at.saturating_add(needle.len())) {
        Some(window) => window == needle,
        None => false,
    }
}

/// Parse ASCII decimal digits to `u32`, refusing empty input,
/// non-digits and overflow.
fn parse_decimal(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for byte in digits.iter() {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte.saturating_sub(b'0')),
            _ => return None,
        };
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    Some(value)
}

/// Scan `bytes` for a Syslinux banner per `0x1400561b0`: `ISOLINUX ` or
/// `SYSLINUX ` (the `LINUX ` tail with an `ISO`/`SYS` head), then a
/// decimal major, a `.`, a decimal minor (each below 256), then the run
/// of characters after the minor up to the first space when it starts
/// with `-` (`6.04-pre1` survives). The digits display raw (`04` stays
/// `04`); the numeric value only gates the below-256 rule. Divergence
/// note: the reference formats `%d.%02d` and treats a zero version as
/// not detected — kept raw here instead, which only differs for banners
/// no producer emits. `<`, `>`, `:`, `|` and `*` become `_`; trailing
/// spaces and `*` trim. Each banner candidate is tried in order and the
/// first that fully parses wins; the suffix run is capped at
/// [`MAX_VERSION_CHARS`] past the minor. The scan window is the whole
/// buffer, while the C starts at `0x40` and stops at `len - 0x40`/`len -
/// 0x20`.
fn syslinux_banner(bytes: &[u8]) -> Option<String> {
    let mut from = 0usize;
    while from < bytes.len() {
        let start = find_sub(bytes, from, b"LINUX ")?;
        let head = match start.checked_sub(3).and_then(|head| bytes.get(head..start)) {
            Some(head) => head,
            None => {
                from = start.saturating_add(1);
                continue;
            }
        };
        if head != b"ISO" && head != b"SYS" {
            from = start.saturating_add(1);
            continue;
        }
        let mut cursor = start.saturating_add(6);
        let major_start = cursor;
        while matches!(bytes.get(cursor), Some(b'0'..=b'9')) {
            cursor = cursor.saturating_add(1);
        }
        // The digits stay raw for display (`04` in `6.04`); the numeric
        // value only gates the < 256 rule.
        let Some(major_text) = bytes
            .get(major_start..cursor)
            .filter(|digits| !digits.is_empty())
        else {
            from = start.saturating_add(1);
            continue;
        };
        if !matches!(parse_decimal(major_text), Some(major) if major < 256) {
            from = start.saturating_add(1);
            continue;
        }
        if bytes.get(cursor) != Some(&b'.') {
            from = start.saturating_add(1);
            continue;
        }
        cursor = cursor.saturating_add(1);
        let minor_start = cursor;
        while matches!(bytes.get(cursor), Some(b'0'..=b'9')) {
            cursor = cursor.saturating_add(1);
        }
        let Some(minor_text) = bytes
            .get(minor_start..cursor)
            .filter(|digits| !digits.is_empty())
        else {
            from = start.saturating_add(1);
            continue;
        };
        if !matches!(parse_decimal(minor_text), Some(minor) if minor < 256) {
            from = start.saturating_add(1);
            continue;
        }
        let mut suffix_end = cursor;
        if bytes.get(cursor) == Some(&b'-') {
            let cap = cursor.saturating_add(MAX_VERSION_CHARS);
            suffix_end = cursor.saturating_add(1);
            while suffix_end < cap {
                match bytes.get(suffix_end) {
                    Some(b' ') | None => break,
                    Some(_) => suffix_end = suffix_end.saturating_add(1),
                }
            }
        }
        let mut version = String::from_utf8_lossy(major_text).into_owned();
        version.push('.');
        version.push_str(&String::from_utf8_lossy(minor_text));
        if let Some(suffix) = bytes.get(cursor..suffix_end) {
            version.push_str(&String::from_utf8_lossy(suffix));
        }
        let clean: String = version
            .chars()
            .map(|next| match next {
                '<' | '>' | ':' | '|' | '*' => '_',
                _ => next,
            })
            .collect();
        return Some(clean.trim_end_matches([' ', '*']).to_string());
    }
    None
}

/// Scan `bytes` for a GRUB banner per `0x14001c200`, which memcmps 16
/// bytes against `"GRUB  version %s"` (two spaces, `%s` included) or 15
/// against `"GRUB version %s"`, then takes the string past the
/// literal's own NUL (`start + 0x11`, `+0x10` for the single-space
/// form) up to the next NUL, trimmed. The earliest banner wins; an
/// empty take keeps scanning. The take is capped at
/// [`MAX_VERSION_CHARS`], the same hostile-input defense as
/// [`syslinux_banner`].
///
/// One linear pass: both literals are tested at each position and the
/// scan advances past the candidate — past the taken NUL, or past the
/// literal when the take is empty — rather than re-scanning the tail,
/// so a buffer of repeated banners costs one walk, not a quadratic one.
fn grub_banner(bytes: &[u8]) -> Option<String> {
    const TWO: &[u8] = b"GRUB  version %s";
    const ONE: &[u8] = b"GRUB version %s";
    let mut at = 0usize;
    while at < bytes.len() {
        let width = if starts_with_at(bytes, at, TWO) {
            TWO.len()
        } else if starts_with_at(bytes, at, ONE) {
            ONE.len()
        } else {
            at = at.saturating_add(1);
            continue;
        };
        // Skip the literal's own NUL, then take to the next NUL.
        let mut end = at.saturating_add(width).saturating_add(1);
        let cap = end.saturating_add(MAX_VERSION_CHARS);
        while end < cap {
            match bytes.get(end) {
                Some(0) | None => break,
                Some(_) => end = end.saturating_add(1),
            }
        }
        let version = match bytes.get(at.saturating_add(width).saturating_add(1)..end) {
            Some(raw) => String::from_utf8_lossy(raw).trim().to_string(),
            None => String::new(),
        };
        if !version.is_empty() {
            return Some(version);
        }
        // Empty take: resume past the literal (its NUL included), so the
        // scan never re-walks ground it already covered.
        at = end.saturating_add(1);
    }
    None
}

/// Boot capability: the El Torito catalog plus the bootloader file
/// rules.
struct BootInfo {
    has_efi: bool,
    has_bios: bool,
    has_syslinux: bool,
    syslinux_version: Option<String>,
    has_grub: bool,
    grub_version: Option<String>,
}

/// Classify boot capability from the tree index, the El Torito catalog
/// (if any) and a binary source for the version scans.
///
/// `has_bios` is true when the catalog holds a bootable entry under
/// platform `0x00`: the initial entry (which sits under the validation
/// platform) or any section entry under its own `0x00` platform. There
/// is deliberately no file fallback — a `bootmgr` or `isolinux.bin`
/// file is not proof the BIOS entry point works; the catalog is.
///
/// `has_efi` is true for a bootable entry under platform `0xEF`, or —
/// when no usable catalog entry says so — for any of [`EFI_FILES`] in
/// the index.
///
/// `has_syslinux` is true for any of [`SYSLINUX_MARKERS`] in the index.
/// `syslinux_version` banner-scans the first present of
/// [`SYSLINUX_BINS`] (first hit in that path order wins); when none
/// yields a version but `has_syslinux` holds, it falls back to `"6.04"`
/// with [`LDLINUX_C32`] present and `"4.07"` without — the
/// embedded-version fallback of `0x14001c640.c:420-495`, which Rufus
/// announces with `Warning: Could not detect Isolinux version -
/// Forcing to %s (embedded)`. Rufus logs `Found conflicting Isolinux
/// versions` when binaries disagree; the report has no log channel, so
/// first hit wins instead. (The version binaries extend beyond the
/// marker list, so a version can surface without `has_syslinux`.)
///
/// `has_grub` is true for any of [`GRUB_MARKERS`] in the index.
/// `grub_version` banner-scans the first present of [`GRUB_BINS`] (same
/// first-hit rule); with no hit it stays `None`, like Rufus's `Could
/// not detect Grub version`.
///
/// The binary source reads through the index-gated handles, so
/// oversized files and directories never buffer; a binary that refuses
/// to read degrades to absent (see [`read_bin`]).
fn classify_boot(
    index: &TreeIndex,
    catalog: Option<&BootCatalog>,
    bin: &dyn Fn(&str) -> Result<Option<Vec<u8>>>,
) -> Result<BootInfo> {
    let mut catalog_bios = false;
    let mut catalog_efi = false;
    if let Some(catalog) = catalog {
        if catalog.initial.bootable {
            match catalog.validation.platform {
                PLATFORM_BIOS => catalog_bios = true,
                PLATFORM_EFI => catalog_efi = true,
                _ => {}
            }
        }
        for section in catalog.sections.iter() {
            for entry in section.entries.iter() {
                if entry.bootable {
                    match section.platform {
                        PLATFORM_BIOS => catalog_bios = true,
                        PLATFORM_EFI => catalog_efi = true,
                        _ => {}
                    }
                }
            }
        }
    }
    let has_bios = catalog_bios;
    let has_efi = catalog_efi || EFI_FILES.iter().any(|marker| index.has(marker));
    let has_syslinux = SYSLINUX_MARKERS.iter().any(|marker| index.has(marker));
    let mut syslinux_version = None;
    for marker in SYSLINUX_BINS {
        let bytes = match bin(marker)? {
            Some(bytes) => bytes,
            None => continue,
        };
        if let Some(version) = syslinux_banner(&bytes) {
            syslinux_version = Some(version);
            break;
        }
    }
    if syslinux_version.is_none() && has_syslinux {
        let embedded = if index.has(LDLINUX_C32) {
            "6.04"
        } else {
            "4.07"
        };
        syslinux_version = Some(embedded.to_string());
    }
    let has_grub = GRUB_MARKERS.iter().any(|marker| index.has(marker));
    let mut grub_version = None;
    for marker in GRUB_BINS {
        let bytes = match bin(marker)? {
            Some(bytes) => bytes,
            None => continue,
        };
        if let Some(version) = grub_banner(&bytes) {
            grub_version = Some(version);
            break;
        }
    }
    Ok(BootInfo {
        has_efi,
        has_bios,
        has_syslinux,
        syslinux_version,
        has_grub,
        grub_version,
    })
}

/// True when the UDF arm must walk for entries: a WIM payload, a distro
/// text file, a persistence config past its marker gate (see
/// [`classify_persistence`]), or a bootloader version binary (see
/// [`classify_boot`]) is marked in the index. Anything else — including
/// a persistence tree with no config marker — never pays for the extra
/// walk.
fn udf_wants_entries(index: &TreeIndex) -> bool {
    index.has(BOOT_WIM)
        || index.has(INSTALL_WIM)
        || index.has(INSTALL_ESD)
        || index.has(DISK_INFO)
        || index.has(README_DISKDEFINES)
        || ((index.has(CASPER_DIR)
            || index.has(CASPER_KERNEL)
            || index.has(LIVE_SQUASHFS)
            || index.has(LIVE_KERNEL))
            && (index.has(ISOLINUX_CFG) || index.has(GRUB_CFG)))
        || SYSLINUX_BINS.iter().any(|marker| index.has(marker))
        || GRUB_BINS.iter().any(|marker| index.has(marker))
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
        let labels = Labels {
            primary: Some(reader.primary().label.clone()),
            joliet: highest_joliet_label(&reader),
            udf: None,
        };
        let disk_info = read_iso_text(&reader, &index, DISK_INFO)?;
        let diskdefines = read_iso_text(&reader, &index, README_DISKDEFINES)?;
        let distro = classify_distro(
            &index,
            &labels,
            disk_info.as_deref(),
            diskdefines.as_deref(),
        );
        // Config greps stay behind the marker gate: no persistence tree,
        // no config reads.
        let track_markers = index.has(CASPER_DIR)
            || index.has(CASPER_KERNEL)
            || index.has(LIVE_SQUASHFS)
            || index.has(LIVE_KERNEL);
        let isolinux_cfg = if track_markers {
            read_iso_text(&reader, &index, ISOLINUX_CFG)?
        } else {
            None
        };
        let grub_cfg = if track_markers {
            read_iso_text(&reader, &index, GRUB_CFG)?
        } else {
            None
        };
        let persistence =
            classify_persistence(&index, isolinux_cfg.as_deref(), grub_cfg.as_deref());
        // The catalog only exists when a boot record names it; a corrupt
        // catalog degrades to "no catalog" so the file-based EFI
        // fallback below still runs — a broken catalog never fails the
        // report.
        let catalog = if reader.boot_records().is_empty() {
            None
        } else {
            reader.boot_catalog().ok()
        };
        let bin_iso = |marker: &str| -> Result<Option<Vec<u8>>> {
            match open_bin_iso(&reader, &index, marker) {
                Some(file) => read_bin(&file),
                None => Ok(None),
            }
        };
        let boot_info = classify_boot(&index, catalog.as_ref(), &bin_iso)?;
        return Ok(ImageReport {
            kind: "iso".to_string(),
            is_iso: true,
            is_windows: windows.is_windows,
            windows_version: windows.windows_version,
            build: windows.build,
            is_windows_to_go: windows.is_windows_to_go,
            wim_images: windows.wim_images,
            distro,
            persistence,
            has_efi: boot_info.has_efi,
            has_bios: boot_info.has_bios,
            has_grub: boot_info.has_grub,
            grub_version: boot_info.grub_version,
            has_syslinux: boot_info.has_syslinux,
            syslinux_version: boot_info.syslinux_version,
            labels,
            truncated: index.is_truncated(),
            ..ImageReport::default()
        });
    }
    if crate::udf::anchor::probe(volume.as_ref()).is_ok() {
        let reader = UdfReader::open(volume)?;
        let index = TreeIndex::from_udf(&reader);
        // The index drops the walked entries the file handles need, so
        // a marked volume pays for one extra walk here (see
        // [`udf_wants_entries`]); any other volume never does. One extra
        // walk total, serving the WIM, text/distro/persistence and
        // binary reasons together — capped here, never one walk per
        // reason. This is the second extra walk overall — the first was
        // slice 3's WIM-only walk, whose trigger set this extends — and
        // a shared entry-carrying index is owed by a later slice.
        let walked = if udf_wants_entries(&index) {
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
        let labels = Labels {
            primary: None,
            joliet: None,
            udf: Some(reader.volume_label().to_string()),
        };
        let disk_info = read_udf_text(&reader, walked, DISK_INFO)?;
        let diskdefines = read_udf_text(&reader, walked, README_DISKDEFINES)?;
        let distro = classify_distro(
            &index,
            &labels,
            disk_info.as_deref(),
            diskdefines.as_deref(),
        );
        let track_markers = index.has(CASPER_DIR)
            || index.has(CASPER_KERNEL)
            || index.has(LIVE_SQUASHFS)
            || index.has(LIVE_KERNEL);
        let isolinux_cfg = if track_markers {
            read_udf_text(&reader, walked, ISOLINUX_CFG)?
        } else {
            None
        };
        let grub_cfg = if track_markers {
            read_udf_text(&reader, walked, GRUB_CFG)?
        } else {
            None
        };
        let persistence =
            classify_persistence(&index, isolinux_cfg.as_deref(), grub_cfg.as_deref());
        // UDF carries no El Torito catalog: on this arm EFI comes from
        // the file fallback alone (see [`classify_boot`]).
        let bin_udf = |marker: &str| -> Result<Option<Vec<u8>>> {
            match open_bin_udf(&reader, walked, marker) {
                Some(file) => read_bin(&file),
                None => Ok(None),
            }
        };
        let boot_info = classify_boot(&index, None, &bin_udf)?;
        return Ok(ImageReport {
            kind: "udf".to_string(),
            is_udf: true,
            is_windows: windows.is_windows,
            windows_version: windows.windows_version,
            build: windows.build,
            is_windows_to_go: windows.is_windows_to_go,
            wim_images: windows.wim_images,
            distro,
            persistence,
            has_efi: boot_info.has_efi,
            has_bios: boot_info.has_bios,
            has_grub: boot_info.has_grub,
            grub_version: boot_info.grub_version,
            has_syslinux: boot_info.has_syslinux,
            syslinux_version: boot_info.syslinux_version,
            labels,
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

    /// One fixture file: identifier, sector, record length, bytes.
    type FixtureFile<'a> = (&'a [u8], u32, u32, Vec<u8>);

    /// Primary-only ISO with subdirectories: the root at sector 20
    /// holds one record per [`FixtureFile`] in `root_files`; each
    /// `(dir_name, files)` in `dirs` becomes a subdirectory (at sectors
    /// 21 and up, in order) holding one record per file the same way.
    /// Each file's `bytes` go to its sector while the record carries
    /// `length`, so a test can lie about a length (for the oversize-text
    /// test the content stays tiny). Identifiers carry the `;1` version
    /// suffix, as real mastering tools write them.
    fn multi_dir_iso(
        label: &str,
        root_files: Vec<FixtureFile<'_>>,
        dirs: Vec<(&[u8], Vec<FixtureFile<'_>>)>,
    ) -> Vec<u8> {
        let mut root = vec![
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        ];
        let mut writes: Vec<(u32, Vec<u8>)> = vec![
            (
                16,
                primary_sector(label, ROOT_SECTOR, SECTOR_BYTES as u32).to_vec(),
            ),
            (17, terminator_sector().to_vec()),
        ];
        for (identifier, sector, length, bytes) in root_files {
            root.push(encode_record(sector, length, 0, identifier));
            writes.push((sector, bytes));
        }
        let mut dir_sector_no = 21u32;
        let mut dir_writes = Vec::new();
        for (dir_name, files) in dirs {
            root.push(encode_record(
                dir_sector_no,
                SECTOR_BYTES as u32,
                FLAG_DIRECTORY,
                dir_name,
            ));
            let mut dir = vec![
                encode_record(dir_sector_no, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            ];
            for (identifier, sector, length, bytes) in files {
                dir.push(encode_record(sector, length, 0, identifier));
                writes.push((sector, bytes));
            }
            dir_writes.push((dir_sector_no, dir_sector(&dir).to_vec()));
            dir_sector_no = dir_sector_no.saturating_add(1);
        }
        writes.push((ROOT_SECTOR, dir_sector(&root).to_vec()));
        writes.extend(dir_writes);
        image_with(&writes)
    }

    /// Primary-only ISO with one subdirectory at sector 21: the same
    /// layout as [`multi_dir_iso`] with the `TESTVOL` label, kept so the
    /// Windows fixtures above stay untouched.
    fn one_dir_iso(
        dir_name: &[u8],
        root_files: &[(&[u8], u32, &[u8])],
        sub_files: &[(&[u8], u32, &[u8])],
    ) -> Vec<u8> {
        multi_dir_iso(
            "TESTVOL",
            root_files
                .iter()
                .map(|(identifier, sector, bytes)| {
                    (*identifier, *sector, bytes.len() as u32, bytes.to_vec())
                })
                .collect(),
            vec![(
                dir_name,
                sub_files
                    .iter()
                    .map(|(identifier, sector, bytes)| {
                        (*identifier, *sector, bytes.len() as u32, bytes.to_vec())
                    })
                    .collect(),
            )],
        )
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

    #[test]
    fn disk_info_and_casper_tree_classify_ubuntu() {
        let info = "Ubuntu 24.04.1 LTS \"Noble Numbat\" - Release amd64 (20240827)\n";
        let iso = multi_dir_iso(
            "Ubuntu 24.04.1 LTS amd64",
            Vec::new(),
            vec![
                (
                    b".DISK".as_slice(),
                    vec![(
                        b"INFO;1".as_slice(),
                        23u32,
                        info.len() as u32,
                        info.as_bytes().to_vec(),
                    )],
                ),
                (
                    b"CASPER".as_slice(),
                    vec![(b"VMLINUZ;1".as_slice(), 24u32, 6, b"kernel".to_vec())],
                ),
            ],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(!report.is_windows);
        assert_eq!(
            report.distro.as_deref(),
            Some("Ubuntu 24.04.1 LTS \"Noble Numbat\"")
        );
        assert_eq!(report.persistence.as_deref(), Some("casper"));
    }

    #[test]
    fn diskdefines_classifies_debian() {
        let defines = "#define ARCH amd64\n#define DISKNAME  Debian GNU/Linux 12.5.0 \"Bookworm\" - Official amd64 NETINST with firmware\n";
        let iso = multi_dir_iso(
            "Debian 12.5.0 amd64",
            vec![(
                b"README.DISKDEFINES;1".as_slice(),
                22u32,
                defines.len() as u32,
                defines.as_bytes().to_vec(),
            )],
            Vec::new(),
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(!report.is_windows);
        assert_eq!(
            report.distro.as_deref(),
            Some("Debian GNU/Linux 12.5.0 \"Bookworm\"")
        );
        assert_eq!(report.persistence, None);
    }

    #[test]
    fn label_rule_classifies_rocky_without_metadata_files() {
        let iso = multi_dir_iso("Rocky-9.3-x86_64", Vec::new(), Vec::new());
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(!report.is_windows);
        assert_eq!(report.distro.as_deref(), Some("Rocky"));
        assert_eq!(report.persistence, None);
    }

    #[test]
    fn live_tree_means_live_persistence() {
        let iso = multi_dir_iso(
            "TESTVOL",
            Vec::new(),
            vec![(
                b"LIVE".as_slice(),
                vec![(
                    b"FILESYSTEM.SQUASHFS;1".as_slice(),
                    23u32,
                    6,
                    b"squash".to_vec(),
                )],
            )],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert_eq!(report.distro, None);
        assert_eq!(report.persistence.as_deref(), Some("live"));
    }

    #[test]
    fn plain_iso_has_no_distro_or_persistence() {
        let iso = multi_dir_iso(
            "TESTVOL",
            vec![(b"README.TXT;1".as_slice(), 22u32, 9, b"plain txt".to_vec())],
            Vec::new(),
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(!report.is_windows);
        assert_eq!(report.distro, None);
        assert_eq!(report.persistence, None);
    }

    #[test]
    fn label_rule_beats_disk_info() {
        // Both a table hit and a metadata file: the table wins.
        let info = "Ubuntu 24.04.1 LTS \"Noble Numbat\" - Release amd64 (20240827)\n";
        let iso = multi_dir_iso(
            "Rocky-9.3-x86_64",
            Vec::new(),
            vec![(
                b".DISK".as_slice(),
                vec![(
                    b"INFO;1".as_slice(),
                    23u32,
                    info.len() as u32,
                    info.as_bytes().to_vec(),
                )],
            )],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert_eq!(report.distro.as_deref(), Some("Rocky"));
    }

    #[test]
    fn oversize_disk_info_is_skipped_without_error() {
        // The record claims 100 KiB while the sector holds almost
        // nothing: the cap refuses before any read, so the missing
        // content is never touched and the analysis succeeds.
        let iso = multi_dir_iso(
            "TESTVOL",
            Vec::new(),
            vec![(
                b".DISK".as_slice(),
                vec![(b"INFO;1".as_slice(), 23u32, 100 * 1024, b"tiny".to_vec())],
            )],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("an oversize file never errors");
        assert_eq!(report.distro, None);
        assert_eq!(report.persistence, None);
    }

    /// One boot entry, bootable when asked, zeroed otherwise.
    fn boot_entry(bootable: bool) -> crate::iso::BootEntry {
        crate::iso::BootEntry {
            bootable,
            media: crate::iso::MediaType::NoEmulation,
            load_segment: 0,
            system_type: 0,
            sector_count: 4,
            load_rba: 34,
        }
    }

    /// A catalog with `validation_platform`, a bootable-when-asked
    /// initial entry, and one bootable-when-asked entry per
    /// `(platform, bootable)` section.
    fn catalog_with(
        validation_platform: u8,
        initial_bootable: bool,
        sections: &[(u8, bool)],
    ) -> BootCatalog {
        BootCatalog {
            validation: crate::iso::ValidationEntry {
                platform: validation_platform,
                id_string: String::new(),
            },
            initial: boot_entry(initial_bootable),
            sections: sections
                .iter()
                .map(|(platform, bootable)| crate::iso::BootSection {
                    is_final: true,
                    platform: *platform,
                    id_string: String::new(),
                    entries: vec![boot_entry(*bootable)],
                })
                .collect(),
        }
    }

    /// No binaries: the path-keyed source for catalog-only tests.
    fn no_bins(_: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// The report carrying `info`'s BIOS/EFI answers, for `boot_mode`.
    fn report_with(info: &BootInfo) -> ImageReport {
        ImageReport {
            has_bios: info.has_bios,
            has_efi: info.has_efi,
            ..ImageReport::default()
        }
    }

    #[test]
    fn catalog_bios_initial_reports_bios_mode() {
        let catalog = catalog_with(0x00, true, &[]);
        let info = classify_boot(&TreeIndex::default(), Some(&catalog), &no_bins)
            .expect("a catalog classifies");
        assert!(info.has_bios);
        assert!(!info.has_efi);
        assert_eq!(report_with(&info).boot_mode(), BootMode::Bios);
    }

    #[test]
    fn catalog_efi_section_reports_uefi_mode() {
        // Validation platform BIOS with a non-bootable initial: only
        // the bootable 0xEF section entry counts.
        let catalog = catalog_with(0x00, false, &[(0xEF, true)]);
        let info = classify_boot(&TreeIndex::default(), Some(&catalog), &no_bins)
            .expect("a catalog classifies");
        assert!(!info.has_bios);
        assert!(info.has_efi);
        assert_eq!(report_with(&info).boot_mode(), BootMode::Uefi);
    }

    #[test]
    fn catalog_with_both_platforms_reports_dual_mode() {
        let catalog = catalog_with(0x00, true, &[(0xEF, true)]);
        let info = classify_boot(&TreeIndex::default(), Some(&catalog), &no_bins)
            .expect("a catalog classifies");
        assert!(info.has_bios);
        assert!(info.has_efi);
        assert_eq!(report_with(&info).boot_mode(), BootMode::Both);
    }

    #[test]
    fn catalog_with_no_bootable_entry_reports_neither() {
        let catalog = catalog_with(0x00, false, &[(0xEF, false)]);
        let info = classify_boot(&TreeIndex::default(), Some(&catalog), &no_bins)
            .expect("a catalog classifies");
        assert!(!info.has_bios);
        assert!(!info.has_efi);
        assert_eq!(report_with(&info).boot_mode(), BootMode::None);
    }

    #[test]
    fn non_bootable_efi_entry_is_not_uefi() {
        let catalog = catalog_with(0xEF, false, &[(0xEF, false)]);
        let info = classify_boot(&TreeIndex::default(), Some(&catalog), &no_bins)
            .expect("a catalog classifies");
        assert!(!info.has_bios);
        assert!(!info.has_efi);
    }

    #[test]
    fn config_without_tree_is_not_persistence() {
        // isolinux.cfg asks for casper, but with no persistence tree the
        // gate keeps the file unread: persistence stays None (while the
        // marker still proves Syslinux).
        let cfg = "DEFAULT linux\nAPPEND boot=casper quiet\n";
        let iso = multi_dir_iso(
            "TESTVOL",
            Vec::new(),
            vec![(
                b"ISOLINUX".as_slice(),
                vec![(
                    b"ISOLINUX.CFG;1".as_slice(),
                    23u32,
                    cfg.len() as u32,
                    cfg.as_bytes().to_vec(),
                )],
            )],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(report.has_syslinux);
        assert_eq!(report.persistence, None);
    }

    #[test]
    fn live_tree_with_casper_config_prefers_casper() {
        // A live tree with a casper kernel option: casper wins.
        let cfg = "DEFAULT linux\nAPPEND boot=casper quiet\n";
        let iso = multi_dir_iso(
            "TESTVOL",
            Vec::new(),
            vec![
                (
                    b"LIVE".as_slice(),
                    vec![(b"VMLINUZ;1".as_slice(), 23u32, 6, b"kernel".to_vec())],
                ),
                (
                    b"ISOLINUX".as_slice(),
                    vec![(
                        b"ISOLINUX.CFG;1".as_slice(),
                        24u32,
                        cfg.len() as u32,
                        cfg.as_bytes().to_vec(),
                    )],
                ),
            ],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert_eq!(report.persistence.as_deref(), Some("casper"));
    }

    #[test]
    fn disk_info_beats_diskdefines() {
        // Both metadata files: the middle precedence step wins.
        let info = "Ubuntu 24.04.1 LTS \"Noble Numbat\" - Release amd64 (20240827)\n";
        let defines = "#define DISKNAME  Debian GNU/Linux 12.5.0 \"Bookworm\" - Official amd64 NETINST with firmware\n";
        let iso = multi_dir_iso(
            "TESTVOL",
            vec![(
                b"README.DISKDEFINES;1".as_slice(),
                22u32,
                defines.len() as u32,
                defines.as_bytes().to_vec(),
            )],
            vec![(
                b".DISK".as_slice(),
                vec![(
                    b"INFO;1".as_slice(),
                    23u32,
                    info.len() as u32,
                    info.as_bytes().to_vec(),
                )],
            )],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert_eq!(
            report.distro.as_deref(),
            Some("Ubuntu 24.04.1 LTS \"Noble Numbat\"")
        );
    }

    #[test]
    fn isolinux_banner_reports_major_minor() {
        let bin = b"\x00\x00ISOLINUX 6.04 0x00000000 extra".to_vec();
        let iso = multi_dir_iso(
            "TESTVOL",
            Vec::new(),
            vec![(
                b"ISOLINUX".as_slice(),
                vec![(b"ISOLINUX.BIN;1".as_slice(), 23u32, bin.len() as u32, bin)],
            )],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(report.has_syslinux);
        assert_eq!(report.syslinux_version.as_deref(), Some("6.04"));
        assert!(!report.has_grub);
    }

    #[test]
    fn syslinux_prerelease_suffix_survives() {
        let bin = b"SYSLINUX 4.07-pre3 0x00000000".to_vec();
        let iso = multi_dir_iso(
            "TESTVOL",
            Vec::new(),
            vec![(
                b"ISOLINUX".as_slice(),
                vec![(b"ISOLINUX.BIN;1".as_slice(), 23u32, bin.len() as u32, bin)],
            )],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(report.has_syslinux);
        assert_eq!(report.syslinux_version.as_deref(), Some("4.07-pre3"));
    }

    #[test]
    fn bannerless_syslinux_falls_back_to_embedded() {
        // No banner anywhere: 6.04 with ldlinux.c32, 4.07 without.
        let bin = b"no banner here".to_vec();
        let with_c32 = multi_dir_iso(
            "TESTVOL",
            Vec::new(),
            vec![(
                b"ISOLINUX".as_slice(),
                vec![
                    (
                        b"ISOLINUX.BIN;1".as_slice(),
                        23u32,
                        bin.len() as u32,
                        bin.clone(),
                    ),
                    (b"LDLINUX.C32;1".as_slice(), 24u32, 4, b"tiny".to_vec()),
                ],
            )],
        );
        let report = analyze(Box::new(memory_volume(&with_c32))).expect("the fixture analyses");
        assert!(report.has_syslinux);
        assert_eq!(report.syslinux_version.as_deref(), Some("6.04"));
        let without_c32 = multi_dir_iso(
            "TESTVOL",
            Vec::new(),
            vec![(
                b"ISOLINUX".as_slice(),
                vec![(b"ISOLINUX.BIN;1".as_slice(), 23u32, bin.len() as u32, bin)],
            )],
        );
        let report = analyze(Box::new(memory_volume(&without_c32))).expect("the fixture analyses");
        assert!(report.has_syslinux);
        assert_eq!(report.syslinux_version.as_deref(), Some("4.07"));
    }

    #[test]
    fn grub_mod_banner_reports_version() {
        // /boot/grub/i386-pc/normal.mod plus its grub.cfg, hand-laid
        // because the GRUB paths nest two deep. The module bytes mirror
        // the measured real layout: the `version %s` literal with its
        // NUL, then the version string with its own NUL.
        let normal_mod =
            b"normal/main.c\x00GNU GRUB  version %s\x002:2.16-1\x00prefix\x00".to_vec();
        let cfg = b"# grub\n".to_vec();
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
                    encode_record(21, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"BOOT"),
                ])
                .to_vec(),
            ),
            (
                21,
                dir_sector(&[
                    encode_record(21, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                    encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                    encode_record(22, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"GRUB"),
                ])
                .to_vec(),
            ),
            (
                22,
                dir_sector(&[
                    encode_record(22, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                    encode_record(21, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                    encode_record(23, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"I386-PC"),
                    encode_record(25, cfg.len() as u32, 0, b"GRUB.CFG;1"),
                ])
                .to_vec(),
            ),
            (
                23,
                dir_sector(&[
                    encode_record(23, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                    encode_record(22, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                    encode_record(24, normal_mod.len() as u32, 0, b"NORMAL.MOD;1"),
                ])
                .to_vec(),
            ),
            (24, normal_mod),
            (25, cfg),
        ]);
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(report.has_grub);
        assert_eq!(report.grub_version.as_deref(), Some("2:2.16-1"));
        assert!(!report.has_syslinux);
        assert_eq!(report.syslinux_version, None);
    }

    #[test]
    fn grub_banner_forms_and_empty_takes() {
        // Single-space literal with a version.
        assert_eq!(
            grub_banner(b"xxGRUB version %s\x001.2\x00"),
            Some("1.2".to_string())
        );
        // An empty take keeps scanning past the literal (double NUL:
        // the take between the literal's NUL and the next is empty).
        assert_eq!(
            grub_banner(b"GRUB  version %s\x00\x00GRUB  version %s\x003.4\x00"),
            Some("3.4".to_string())
        );
        // No banner at all.
        assert_eq!(grub_banner(b"nothing here"), None);
    }

    #[test]
    fn repeated_empty_grub_banners_stay_linear() {
        // The adversarial shape for a re-scanning loop: a cap-sized
        // buffer of empty-take banners (`%s` literal, NUL, NUL). The
        // single pass walks it once, so this returns in the suite's
        // normal runtime with no version found — no timing assert, just
        // the result (a quadratic loop would time the suite out here).
        let unit = b"GRUB  version %s\x00\x00";
        let mut bytes = Vec::new();
        while bytes.len().saturating_add(unit.len()) <= MAX_BINARY_SCAN as usize {
            bytes.extend_from_slice(unit);
        }
        assert_eq!(grub_banner(&bytes), None);
    }

    #[test]
    fn efi_file_alone_reports_uefi_without_bios() {
        // No catalog section at all: the file fallback proves UEFI.
        let iso = multi_dir_iso(
            "TESTVOL",
            Vec::new(),
            vec![(
                b"BOOT".as_slice(),
                vec![(b"EFI.IMG;1".as_slice(), 23u32, 8, b"fatimage".to_vec())],
            )],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(report.has_efi);
        assert!(!report.has_bios);
        assert_eq!(report.boot_mode(), BootMode::Uefi);
    }

    #[test]
    fn plain_iso_has_no_boot_paths() {
        let iso = multi_dir_iso(
            "TESTVOL",
            vec![(b"README.TXT;1".as_slice(), 22u32, 9, b"plain txt".to_vec())],
            Vec::new(),
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert!(!report.has_efi);
        assert!(!report.has_bios);
        assert!(!report.has_grub);
        assert_eq!(report.grub_version, None);
        assert!(!report.has_syslinux);
        assert_eq!(report.syslinux_version, None);
        assert_eq!(report.boot_mode(), BootMode::None);
    }

    #[test]
    fn oversize_isolinux_bin_falls_back_without_reading() {
        // The record claims past MAX_BINARY_SCAN while the sector holds
        // almost nothing: the size gate skips the read, and the
        // embedded fallback still answers (no ldlinux.c32, so 4.07).
        let iso = multi_dir_iso(
            "TESTVOL",
            Vec::new(),
            vec![(
                b"ISOLINUX".as_slice(),
                vec![(
                    b"ISOLINUX.BIN;1".as_slice(),
                    23u32,
                    (MAX_BINARY_SCAN as u32).saturating_add(1),
                    b"tiny".to_vec(),
                )],
            )],
        );
        let report =
            analyze(Box::new(memory_volume(&iso))).expect("an oversize binary never errors");
        assert!(report.has_syslinux);
        assert_eq!(report.syslinux_version.as_deref(), Some("4.07"));
    }

    #[test]
    fn kolibri_marker_reports_kolibrios() {
        let iso = multi_dir_iso(
            "TESTVOL",
            vec![(b"KOLIBRI.IMG;1".as_slice(), 22u32, 4, b"dos".to_vec())],
            Vec::new(),
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert_eq!(report.distro.as_deref(), Some("KolibriOS"));
    }

    #[test]
    fn setupldr_marker_reports_reactos() {
        let iso = multi_dir_iso(
            "TESTVOL",
            vec![(b"SETUPLDR.SYS;1".as_slice(), 22u32, 4, b"dos".to_vec())],
            Vec::new(),
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert_eq!(report.distro.as_deref(), Some("ReactOS"));
    }

    #[test]
    fn kernel_and_fdconfig_markers_report_freedos() {
        let iso = multi_dir_iso(
            "TESTVOL",
            vec![
                (b"KERNEL.SYS;1".as_slice(), 22u32, 4, b"dos".to_vec()),
                (b"FDCONFIG.SYS;1".as_slice(), 23u32, 4, b"dos".to_vec()),
            ],
            Vec::new(),
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert_eq!(report.distro.as_deref(), Some("FreeDOS"));
    }

    #[test]
    fn io_and_msdos_markers_report_msdos() {
        let iso = multi_dir_iso(
            "TESTVOL",
            vec![
                (b"IO.SYS;1".as_slice(), 22u32, 4, b"dos".to_vec()),
                (b"MSDOS.SYS;1".as_slice(), 23u32, 4, b"dos".to_vec()),
            ],
            Vec::new(),
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert_eq!(report.distro.as_deref(), Some("MS-DOS"));
    }

    #[test]
    fn dos_marker_beats_label_rule_and_disk_info() {
        // A DOS marker, a table-hit label and a metadata file together:
        // the marker wins over both later steps.
        let info = "Ubuntu 24.04.1 LTS \"Noble Numbat\" - Release amd64 (20240827)\n";
        let iso = multi_dir_iso(
            "Rocky-9.3-x86_64",
            vec![(b"KOLIBRI.IMG;1".as_slice(), 22u32, 4, b"dos".to_vec())],
            vec![(
                b".DISK".as_slice(),
                vec![(
                    b"INFO;1".as_slice(),
                    23u32,
                    info.len() as u32,
                    info.as_bytes().to_vec(),
                )],
            )],
        );
        let report = analyze(Box::new(memory_volume(&iso))).expect("the fixture analyses");
        assert_eq!(report.distro.as_deref(), Some("KolibriOS"));
    }
}
