//! The UDF reader: open, label, revision, NSR, listings, file reads and
//! walks (S15, slices 1-2).
//!
//! [`UdfReader::open`] walks the whole chain up front — recognition
//! sequence, anchor probe, main (or reserve) descriptor sequence, file
//! set descriptor, root file entry — so any malformed volume refuses at
//! open time, before any listing. [`UdfReader::read_dir`] then lists any
//! directory entry by resolving its ICB through the partition maps;
//! [`UdfReader::open_file`]/[`UdfReader::read_file`] read regular files
//! the same way, and [`UdfReader::walk`] lists the whole tree.
//!
//! *Measured* — the chain above parses byte-identical on the `mkudffs`
//! images from udftools 2.3 (see [`udf`](super) and the slice reports):
//! the label reads `LABEL`, the revision `2.01`, the NSR `NSR03`; small
//! files and directories read embedded straight from their entries
//! (an 88-byte subdirectory, a 19-byte file, a 14-byte file holding a
//! NUL byte and non-ASCII content, a 3-byte file, each returned
//! byte-exact); a 10000-byte file reads back byte-identical through one
//! long extent. Multi-extent directories, symlinks (type 12) and FIFOs
//! (type 9) are synthetic-fixture facts: the unit tests join two directory
//! extents and refuse symlinks and FIFOs in both directions with their
//! kind named.
//!
//! *Inferred* — that accepting both `NSR02` and `NSR03` is right (the
//! writer side pins `NSR03` and refuses `NSR02`; a *reader* that refused
//! `NSR02` images would turn away every `--udfrev=0x0150` volume for no
//! structural reason, so the recognition mirror below accepts both while
//! keeping every other byte check identical to
//! [`recognition`](crate::fs::udf::recognition)).

use std::fmt;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::fs::udf::Nsr;
use crate::text::device_text;
use crate::udf::LongAd;
use crate::udf::MAX_FILE_EXTENTS;
use crate::udf::MAX_WALK_DEPTH;
use crate::udf::PartitionDesc;
use crate::udf::anchor;
use crate::udf::descriptor;
use crate::udf::fid;
use crate::udf::file;
use crate::udf::read_bytes;
use crate::udf::unicode;

/// Absolute byte offset of the volume recognition sequence: three
/// consecutive 2048-byte sectors, identical for both block sizes.
const RECOGNITION_AT: u64 = 32768;
/// Length of the recognition region in bytes.
const RECOGNITION_LEN: u64 = 3 * 2048;

/// One directory entry: the decoded name, the directory flag and the ICB
/// slice 2 needs to read the entry's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Decoded file name (OSTA compressed Unicode). Empty for the root,
    /// which has no name.
    pub name: String,
    /// True for directories (characteristics bit 1).
    pub is_directory: bool,
    /// Long address of the entry's file entry: extent length, block
    /// number (partition-relative) and partition reference.
    pub icb: LongAd,
    /// File version number from the file identifier (1 on real images).
    pub file_version: u16,
}

/// An opened regular file: the resolved extent windows (or the embedded
/// bytes) with the information length. The addressing stays inside the
/// handle so every read clamps to the length: callers cannot bypass the
/// truncation, and the file type was already gated at
/// [`UdfReader::open_file`]. Read it with [`UdfReader::read_open`] or
/// [`UdfReader::read_open_at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFile {
    /// Absolute byte windows in file order (empty for embedded files).
    windows: Vec<file::ResolvedExtent>,
    /// Embedded file bytes cut to the information length (empty for
    /// extent-backed files).
    embedded: Vec<u8>,
    /// Information length in bytes: every read stops here.
    size: u64,
    /// Entry name, for error messages only.
    name: String,
}

impl OpenFile {
    /// File length in bytes (the information length).
    #[must_use]
    pub fn len(&self) -> u64 {
        self.size
    }

    /// True when the file holds no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Entry name the file was opened from.
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.name
    }
}

/// UDF reader over an owned byte store: the anchor, the descriptor
/// sequence, the partition table, the file set and the root ICB, all
/// resolved at [`UdfReader::open`]. No `Debug` derive: the owned
/// `Box<dyn Volume>` store carries none, and a reader needs no debug
/// view.
pub struct UdfReader {
    /// The backing byte store; reads go straight through it with checked
    /// windows (no cache — see [`udf`](super) for why).
    volume: Box<dyn Volume>,
    /// Total store extent in bytes.
    total: u64,
    /// Probed logical block size in bytes.
    block_size: u32,
    /// Recognition sequence NSR (`NSR02` or `NSR03`).
    nsr: Nsr,
    /// Logical volume identifier (d-string, padding trimmed, sanitised).
    label: String,
    /// Domain suffix revision (`2.01` for the pinned writer revision).
    revision: String,
    /// Partition numbers in map-table order.
    maps: Vec<u16>,
    /// Partition descriptors in walk order.
    partitions: Vec<PartitionDesc>,
    /// Partition the root ICB resolves through.
    home: PartitionDesc,
    /// File set descriptor (the root ICB lives here).
    fsd: file::FileSetDescriptor,
}

/// Debug without the byte store: the owned `Box<dyn Volume>` carries no
/// debug view, so the format covers the parsed metadata only.
impl fmt::Debug for UdfReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdfReader")
            .field("total", &self.total)
            .field("block_size", &self.block_size)
            .field("nsr", &self.nsr)
            .field("label", &self.label)
            .field("revision", &self.revision)
            .field("maps", &self.maps)
            .field("partitions", &self.partitions)
            .field("home", &self.home)
            .field("fsd", &self.fsd)
            .finish()
    }
}

impl UdfReader {
    /// Open the volume: verify the recognition sequence, probe the anchor
    /// at sector 256, walk the main descriptor sequence (falling back to
    /// the reserve copy when the main one is incomplete), then resolve the
    /// file set descriptor and validate the root file entry. Any malformed
    /// structure refuses here, naming the block and the numbers.
    pub fn open(volume: Box<dyn Volume>) -> Result<Self> {
        let total = volume.total_bytes();
        let nsr = read_nsr(&*volume, total)?;
        let anchor = anchor::probe(&*volume)?;
        let size = anchor.block_size;
        let walked = descriptor::walk(&*volume, size, anchor.main, total);
        let set = match walked {
            Ok(set) if set.is_complete() => set,
            _ => match anchor.reserve {
                Some(reserve) => {
                    let fallback = descriptor::walk(&*volume, size, reserve, total)?;
                    if !fallback.is_complete() {
                        // Both sequences walked; report the main one's
                        // failure, which the fallback did not repair.
                        walked?;
                    }
                    fallback
                }
                None => walked?,
            },
        };
        let logical = set.logical.as_ref().ok_or_else(|| {
            CoreError::invalid("volume descriptor walk returned no logical volume")
        })?;
        let fsd_rel = logical.fsd.lbn;
        let fsd_part = file::resolve_map(
            &logical.maps,
            &set.partitions,
            logical.fsd.partition_ref,
            "file set descriptor",
        )?;
        let fsd_abs = fsd_part.start.checked_add(fsd_rel).ok_or_else(|| {
            CoreError::invalid(format!(
                "file set descriptor at partition-relative block {fsd_rel} overflows the block number"
            ))
        })?;
        let fsd = file::read_fsd(&*volume, size, fsd_abs, fsd_rel)?;
        let home = file::resolve_map(
            &logical.maps,
            &set.partitions,
            fsd.root_icb.partition_ref,
            "root directory",
        )?;
        let root_abs = home.start.checked_add(fsd.root_icb.lbn).ok_or_else(|| {
            CoreError::invalid(format!(
                "root directory at partition-relative block {} overflows the block number",
                fsd.root_icb.lbn
            ))
        })?;
        check_icb_window(size, total, &fsd.root_icb, root_abs, "root directory")?;
        // Validate the root file entry now so a corrupt root refuses at
        // open time, exactly like the rest of the chain.
        file::read_file_entry(&*volume, size, root_abs, fsd.root_icb.lbn)?;
        let label = device_text(&logical.label);
        Ok(Self {
            volume,
            total,
            block_size: size,
            nsr,
            label,
            revision: logical.revision.clone(),
            maps: logical.maps.clone(),
            partitions: set.partitions,
            home,
            fsd,
        })
    }

    /// Volume label from the logical volume identifier (d-string, padding
    /// trimmed, sanitised to ASCII).
    #[must_use]
    pub fn volume_label(&self) -> &str {
        &self.label
    }

    /// UDF revision from the domain suffix (`2.01` for the pinned writer
    /// revision).
    #[must_use]
    pub fn udf_revision(&self) -> &str {
        &self.revision
    }

    /// Volume recognition sequence NSR (`NSR02` or `NSR03`).
    #[must_use]
    pub fn nsr(&self) -> Nsr {
        self.nsr
    }

    /// Logical block size in bytes (512 or 2048).
    #[must_use]
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Total store extent in bytes.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total
    }

    /// Partition number the root resolves through.
    #[must_use]
    pub fn partition_number(&self) -> u16 {
        self.home.number
    }

    /// First absolute block number of that partition.
    #[must_use]
    pub fn partition_start(&self) -> u32 {
        self.home.start
    }

    /// That partition's length in blocks.
    #[must_use]
    pub fn partition_length(&self) -> u32 {
        self.home.length
    }

    /// The file set descriptor (carries the root ICB).
    #[must_use]
    pub fn fsd(&self) -> &file::FileSetDescriptor {
        &self.fsd
    }

    /// The root directory entry (empty name, always a directory),
    /// synthesised from the file set's root ICB.
    #[must_use]
    pub fn root(&self) -> Entry {
        Entry {
            name: String::new(),
            is_directory: true,
            icb: self.fsd.root_icb,
            file_version: 1,
        }
    }

    /// List `entry` (the root or any directory entry): resolve its ICB
    /// through the partition maps, read its file entry, join its data and
    /// parse the file identifiers. Deleted entries (bit 2) and parent
    /// entries (bit 3) are skipped, exactly like ISO skips dot records;
    /// hidden entries (bit 0) list normally. Refuses non-directories (a
    /// symlink gets its own message: symlinks are never followed),
    /// unresolvable ICBs and malformed directory data, naming the entry.
    /// A directory whose identifiers span several extents lists all of
    /// them: the extents join in order before parsing.
    pub fn read_dir(&self, entry: &Entry) -> Result<Vec<Entry>> {
        let display = short_name(&entry.name);
        let (home, abs, rel) = self.resolve(&entry.icb, &display)?;
        check_icb_window(self.block_size, self.total, &entry.icb, abs, &display)?;
        let file_entry = file::read_file_entry(&*self.volume, self.block_size, abs, rel)
            .map_err(|error| CoreError::invalid(format!("cannot list `{display}`: {error}")))?;
        if file_entry.file_type == file::TYPE_SYMLINK {
            return Err(CoreError::invalid(format!(
                "cannot list `{display}`: it is a symbolic link, not a directory: \
                 symlinks are listed but never followed"
            )));
        }
        if file_entry.file_type != file::TYPE_DIRECTORY {
            return Err(CoreError::invalid(format!(
                "cannot list `{display}`: it is a {}, not a directory",
                file::file_type_name(file_entry.file_type)
            )));
        }
        let what = format!("directory `{display}`");
        let (data, segs) = file::collect_data(
            &*self.volume,
            self.block_size,
            &self.maps,
            &self.partitions,
            &home,
            &file_entry,
            &what,
            rel,
        )
        .map_err(|error| CoreError::invalid(format!("cannot list `{display}`: {error}")))?;
        let ids = fid::parse_fids(&data, &segs, self.block_size, &what)
            .map_err(|error| CoreError::invalid(format!("cannot list `{display}`: {error}")))?;
        let mut out = Vec::new();
        for id in &ids {
            if id.is_deleted() || id.is_parent() {
                continue;
            }
            let name = unicode::decode_osta(
                &id.name,
                &format!("{what} entry at directory offset {}", id.name_off),
            )
            .map_err(|error| CoreError::invalid(format!("cannot list `{display}`: {error}")))?;
            out.push(Entry {
                name,
                is_directory: id.is_directory,
                icb: id.icb,
                file_version: id.version,
            });
        }
        Ok(out)
    }

    /// Open the regular file `entry` for reading with
    /// [`UdfReader::read_open`]: resolve its ICB, gate its file type and
    /// resolve its extents against their partitions. Only regular files
    /// (type 5) open: directories, symlinks (whose targets are
    /// path-component records this reader does not decode), FIFOs,
    /// sockets, devices and anything else refuse with the kind named.
    /// Embedded files (allocation type 3) carry their bytes in the
    /// handle; extent-backed files resolve to absolute byte windows.
    pub fn open_file(&self, entry: &Entry) -> Result<OpenFile> {
        let display = short_name(&entry.name);
        let (home, abs, rel) = self.resolve(&entry.icb, &display)?;
        check_icb_window(self.block_size, self.total, &entry.icb, abs, &display)?;
        let file_entry = file::read_file_entry(&*self.volume, self.block_size, abs, rel)
            .map_err(|error| CoreError::invalid(format!("cannot open `{display}`: {error}")))?;
        match file_entry.file_type {
            file::TYPE_FILE => {}
            file::TYPE_DIRECTORY => {
                return Err(CoreError::invalid(format!(
                    "cannot open `{display}`: it is a directory, not a regular file"
                )));
            }
            file::TYPE_SYMLINK => {
                return Err(CoreError::invalid(format!(
                    "cannot open `{display}`: it is a symbolic link, not a regular file: \
                     symlink targets are path-component records this reader does not decode, \
                     so symlinks are listed but never followed"
                )));
            }
            other => {
                return Err(CoreError::invalid(format!(
                    "cannot open `{display}`: it is a {}, not a regular file: only regular \
                     files open for reading",
                    file::file_type_name(other)
                )));
            }
        }
        let what = format!("file `{display}`");
        if file_entry.ads.is_empty() {
            let len = usize::try_from(file_entry.info_len).map_err(|_| {
                CoreError::invalid(format!(
                    "cannot open `{display}`: information length {} is not addressable",
                    file_entry.info_len
                ))
            })?;
            let data = file_entry.embedded.get(..len).ok_or_else(|| {
                CoreError::invalid(format!(
                    "cannot open `{display}`: information length {} runs past the {} embedded \
                     bytes",
                    file_entry.info_len,
                    file_entry.embedded.len()
                ))
            })?;
            return Ok(OpenFile {
                windows: Vec::new(),
                embedded: data.to_vec(),
                size: file_entry.info_len,
                name: display,
            });
        }
        let windows = file::resolve_extents(
            self.block_size,
            &self.maps,
            &self.partitions,
            &home,
            &file_entry.ads,
            &what,
            MAX_FILE_EXTENTS,
        )
        .map_err(|error| CoreError::invalid(format!("cannot open `{display}`: {error}")))?;
        file::check_file_bounds(file_entry.info_len, &windows, &what)
            .map_err(|error| CoreError::invalid(format!("cannot open `{display}`: {error}")))?;
        Ok(OpenFile {
            windows,
            embedded: Vec::new(),
            size: file_entry.info_len,
            name: display,
        })
    }

    /// Read the whole regular file `entry` into RAM: opens it, then reads
    /// through [`UdfReader::read_open`]. Only the information length
    /// returns even when the extents sum past it; a short sum refuses at
    /// open time.
    pub fn read_file(&self, entry: &Entry) -> Result<Vec<u8>> {
        let file = self.open_file(entry)?;
        self.read_open(&file).map_err(|error| {
            CoreError::invalid(format!(
                "cannot read `{}`: {error}",
                short_name(&entry.name)
            ))
        })
    }

    /// Read the whole opened file into RAM: embedded bytes clone out of
    /// the handle, extent windows read in file order and clamp at the
    /// information length. An empty file reads nothing; any window running
    /// past the store refuses as truncation with the numbers named.
    pub fn read_open(&self, file: &OpenFile) -> Result<Vec<u8>> {
        if file.size == 0 {
            return Ok(Vec::new());
        }
        if !file.embedded.is_empty() {
            return Ok(file.embedded.clone());
        }
        let what = format!("file `{}`", short_name(&file.name));
        file::read_windows(&*self.volume, &file.windows, file.size, &what).map_err(|error| {
            CoreError::invalid(format!("cannot read `{}`: {error}", short_name(&file.name)))
        })
    }

    /// Read up to `buf.len()` bytes of the regular file `entry` at
    /// `offset`: opens it, then reads through
    /// [`UdfReader::read_open_at`]. Returns the bytes placed (0 at end of
    /// file).
    pub fn read_file_at(&self, entry: &Entry, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let file = self.open_file(entry)?;
        self.read_open_at(&file, offset, buf).map_err(|error| {
            CoreError::invalid(format!(
                "cannot read `{}`: {error}",
                short_name(&entry.name)
            ))
        })
    }

    /// Read up to `buf.len()` bytes of the opened file at `offset`:
    /// returns the bytes placed (0 at end of file). Refuses an offset past
    /// the length, naming both; every window read is bounds-checked before
    /// its I/O.
    pub fn read_open_at(&self, file: &OpenFile, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let name = short_name(&file.name);
        if !file.windows.is_empty() {
            let what = format!("file `{name}`");
            return file::read_windows_at(
                &*self.volume,
                &file.windows,
                file.size,
                offset,
                buf,
                &what,
            )
            .map_err(|error| CoreError::invalid(format!("cannot read `{name}`: {error}")));
        }
        if offset > file.size {
            return Err(CoreError::invalid(format!(
                "cannot read `{name}` at offset {offset}: past the {} byte file",
                file.size
            )));
        }
        if buf.is_empty() || offset == file.size {
            return Ok(0);
        }
        let start = usize::try_from(offset).map_err(|_| {
            CoreError::invalid(format!(
                "cannot read `{name}` at offset {offset}: not addressable"
            ))
        })?;
        let want = (file.size.saturating_sub(offset)).min(buf.len() as u64);
        let count = usize::try_from(want).map_err(|_| {
            CoreError::invalid(format!(
                "cannot read `{name}` of {want} bytes: not addressable"
            ))
        })?;
        let end = start.saturating_add(count);
        let embedded_len = file.embedded.len();
        let src = file.embedded.get(start..end).ok_or_else(|| {
            CoreError::invalid(format!(
                "cannot read `{name}` bytes {start}..{end} past the {embedded_len} embedded bytes"
            ))
        })?;
        let buffer_len = buf.len();
        let dest = buf.get_mut(..count).ok_or_else(|| {
            CoreError::invalid(format!(
                "cannot read `{name}` of {count} bytes past the {buffer_len} byte buffer"
            ))
        })?;
        dest.copy_from_slice(src);
        Ok(count)
    }

    /// Depth-first listing over the whole tree: the root as (`/`, root)
    /// first, then every descendant pre-order as (`/A`, `/A/B`, ...) with
    /// its [`Entry`]. Paths are absolute (leading `/`) and only
    /// directories descend — symlinks list but never descend (opening one
    /// refuses anyway). Descent past
    /// [`MAX_WALK_DEPTH`](crate::udf::MAX_WALK_DEPTH) refuses as a
    /// possible directory loop: corrupt ICBs that cycle refuse here
    /// rather than hanging. A hostile name containing `/` yields an
    /// ambiguous path the entry still carries verbatim.
    pub fn walk(&self) -> Result<Vec<(String, Entry)>> {
        let root = self.root();
        let mut out = Vec::new();
        out.push(("/".to_string(), root.clone()));
        self.walk_dir(&root, "/", 0, &mut out)?;
        Ok(out)
    }

    /// One level of [`UdfReader::walk`]: list `dir`, push one (`path`,
    /// entry) pair per child, and descend into directories. `depth` counts
    /// descents from the root; past
    /// [`MAX_WALK_DEPTH`](crate::udf::MAX_WALK_DEPTH) the tree cycles, so
    /// the walk refuses instead.
    fn walk_dir(
        &self,
        dir: &Entry,
        path: &str,
        depth: usize,
        out: &mut Vec<(String, Entry)>,
    ) -> Result<()> {
        if depth > MAX_WALK_DEPTH {
            return Err(CoreError::invalid(format!(
                "walk of `{}` nests past {MAX_WALK_DEPTH} directories: refusing as a possible \
                 directory loop",
                short_name(path)
            )));
        }
        let children = self
            .read_dir(dir)
            .map_err(|error| CoreError::invalid(format!("cannot walk `{path}`: {error}")))?;
        for child in &children {
            // Paths carry the decoded name verbatim (not the sanitised
            // error form): a hostile `/` inside a name yields an ambiguous
            // path, documented above.
            let child_path = if path == "/" {
                format!("/{}", child.name)
            } else {
                format!("{path}/{}", child.name)
            };
            out.push((child_path.clone(), child.clone()));
            if child.is_directory {
                self.walk_dir(child, &child_path, depth.saturating_add(1), out)?;
            }
        }
        Ok(())
    }

    /// Resolve an ICB to its partition, absolute block and
    /// partition-relative block: the partition reference indexes the map
    /// table, the map gives the partition number, and the block adds onto
    /// the partition start. Slice 2 builds file reads on this. Refuses an
    /// unresolvable reference or an overflowing block sum.
    pub fn resolve_icb(&self, icb: &LongAd) -> Result<(u32, u32)> {
        let display = short_name("<icb>");
        let (_, abs, _) = self.resolve(icb, &display)?;
        Ok((abs, icb.extent_length))
    }

    /// Resolve `icb` to (partition, absolute block, relative block).
    fn resolve(&self, icb: &LongAd, display: &str) -> Result<(PartitionDesc, u32, u32)> {
        let home = file::resolve_map(&self.maps, &self.partitions, icb.partition_ref, display)?;
        let abs = home.start.checked_add(icb.lbn).ok_or_else(|| {
            CoreError::invalid(format!(
                "{display} at partition-relative block {} overflows the block number",
                icb.lbn
            ))
        })?;
        Ok((home, abs, icb.lbn))
    }
}

/// The ICB window must hold the addressed block: refuses a zero length, a
/// length past one block (file entries fill exactly their block in slice
/// 1; longer ICBs belong to a later slice) and a window running past the
/// store — each naming the numbers.
fn check_icb_window(size: u32, total: u64, icb: &LongAd, abs: u32, display: &str) -> Result<()> {
    if icb.extent_length == 0 {
        return Err(CoreError::invalid(format!(
            "{display} ICB has zero length: no file entry to read"
        )));
    }
    if icb.extent_length > size {
        return Err(CoreError::invalid(format!(
            "{display} ICB length {} runs past the {size} byte block size: multi-block file \
             entries are not supported",
            icb.extent_length
        )));
    }
    let offset = u64::from(abs).checked_mul(u64::from(size)).ok_or_else(|| {
        CoreError::invalid(format!(
            "{display} ICB at block {abs} overflows the byte offset arithmetic"
        ))
    })?;
    let end = offset.checked_add(u64::from(size)).ok_or_else(|| {
        CoreError::invalid(format!(
            "{display} ICB of {size} bytes at block {abs} overflows the byte offset arithmetic"
        ))
    })?;
    if end > total {
        return Err(CoreError::invalid(format!(
            "{display} ICB of {size} bytes at block {abs} (bytes {offset}..{end}) runs past \
             the {total} byte volume end"
        )));
    }
    Ok(())
}

/// Error-message form of an entry name: sanitised to ASCII and capped at
/// 200 characters so a hostile name cannot flood a log line.
fn short_name(name: &str) -> String {
    let clean = if name.is_empty() {
        String::from("/")
    } else {
        device_text(name)
    };
    let mut out: String = clean.chars().take(200).collect();
    if clean.chars().count() > 200 {
        out.push_str("...");
    }
    out
}

/// Verify the volume recognition sequence at absolute bytes 32768..38912:
/// three 2048-byte sectors opening with struct type `0x00`, identifiers
/// `BEA01`/`NSR02`-or-`NSR03`/`TEA01` and struct version `0x01`. Every
/// check mirrors [`recognition`](crate::fs::udf::recognition) except the
/// middle identifier, which accepts both revisions (see the module
/// header). Refusals name the absolute offsets and the bytes found.
fn read_nsr(volume: &dyn Volume, total: u64) -> Result<Nsr> {
    let region = read_bytes(
        volume,
        RECOGNITION_AT,
        RECOGNITION_LEN,
        total,
        "UDF recognition",
    )?;
    check_sector(&region, 0, "BEA01")?;
    let nsr = check_nsr(&region)?;
    check_sector(&region, 2, "TEA01")?;
    Ok(nsr)
}

/// Check one recognition sector's type byte, ASCII identifier and version
/// byte: sector `index` (0 or 2) starts at absolute byte
/// `32768 + index * 2048`.
fn check_sector(region: &[u8], index: usize, expected: &str) -> Result<()> {
    let base = index.saturating_mul(2048);
    let start = (RECOGNITION_AT as usize).saturating_add(base);
    check_type_byte(region, base, start)?;
    let identifier = sector_identifier(region, base, start)?;
    if identifier != expected {
        return Err(identifier_mismatch(start, &identifier, expected));
    }
    check_version_byte(region, base, start)?;
    Ok(())
}

/// Check the middle recognition sector (absolute byte 34816): the type
/// and version bytes read like every sector, while the identifier may be
/// either revision's NSR — `NSR03` or `NSR02` — and anything else refuses
/// naming the expected identifiers.
fn check_nsr(region: &[u8]) -> Result<Nsr> {
    let base = 2048;
    let start = (RECOGNITION_AT as usize).saturating_add(base);
    check_type_byte(region, base, start)?;
    let identifier = sector_identifier(region, base, start)?;
    if identifier == Nsr::Nsr03.as_str() {
        check_version_byte(region, base, start)?;
        return Ok(Nsr::Nsr03);
    }
    if identifier == Nsr::Nsr02.as_str() {
        check_version_byte(region, base, start)?;
        return Ok(Nsr::Nsr02);
    }
    Err(CoreError::invalid(format!(
        "the UDF recognition sector at byte {start} reads `{identifier}` not `NSR03` or \
         `NSR02`: bytes {}..{} must read an NSR identifier",
        start + 1,
        start + 6,
    )))
}

/// Byte 0 of the sector at region offset `base` (absolute `start`) is the
/// struct type `0x00`.
fn check_type_byte(region: &[u8], base: usize, start: usize) -> Result<()> {
    let found = region.get(base).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "the UDF recognition region ends before the struct type byte at byte {start}"
        ))
    })?;
    if found != 0x00 {
        return Err(CoreError::invalid(format!(
            "the UDF recognition sector at byte {start} has struct type 0x{found:02X} \
              not 0x00: byte {start} must read 0x00"
        )));
    }
    Ok(())
}

/// Bytes 1..6 of the sector at region offset `base` as sanitised text.
fn sector_identifier(region: &[u8], base: usize, start: usize) -> Result<String> {
    let bytes = region.get(base + 1..base + 6).ok_or_else(|| {
        CoreError::invalid(format!(
            "the UDF recognition region ends before the identifier bytes {}..{} of the \
             sector at byte {start}",
            start + 1,
            start + 6,
        ))
    })?;
    Ok(device_text(&String::from_utf8_lossy(bytes)))
}

/// Byte 6 of the sector at region offset `base` (absolute `start`) is the
/// struct version `0x01`.
fn check_version_byte(region: &[u8], base: usize, start: usize) -> Result<()> {
    let at = start.saturating_add(6);
    let found = region.get(base + 6).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "the UDF recognition region ends before the struct version byte at byte {at}"
        ))
    })?;
    if found != 0x01 {
        return Err(CoreError::invalid(format!(
            "the UDF recognition sector at byte {start} has struct version 0x{found:02X} \
              not 0x01: byte {at} must read 0x01"
        )));
    }
    Ok(())
}

/// Refusal for a recognition sector whose identifier is not `expected`.
fn identifier_mismatch(start: usize, found: &str, expected: &str) -> CoreError {
    CoreError::invalid(format!(
        "the UDF recognition sector at byte {start} reads `{found}` not `{expected}`: \
          bytes {}..{} must read the {expected} identifier",
        start + 1,
        start + 6,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::udf::stamp_tag;

    const SIZE: u32 = 512;
    /// Absolute block of the anchor (sector 256 in 512-byte units).
    const ANCHOR_AT: u32 = 256;
    /// Main sequence extent: 8 blocks from 96 on.
    const MAIN_AT: u32 = 96;
    /// Partition start both fixtures use.
    const PART_AT: u32 = 257;

    /// Recognition region: BEA01, NSR03, TEA01.
    fn recognition(nsr: &[u8; 5]) -> Vec<u8> {
        let mut region = vec![0u8; 6144];
        for (index, id) in [*b"BEA01", *nsr, *b"TEA01"].iter().enumerate() {
            let base = index * 2048;
            region[base] = 0x00;
            region[base + 1..base + 6].copy_from_slice(id);
            region[base + 6] = 0x01;
        }
        region
    }

    /// Anchor block with a main extent (`MAIN_AT`, 8 blocks) and no
    /// reserve, CRC fixed.
    fn anchor() -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        block[16..20].copy_from_slice(&(8 * SIZE).to_le_bytes());
        block[20..24].copy_from_slice(&MAIN_AT.to_le_bytes());
        stamp_tag(&mut block, 2, (SIZE - 16) as u16, ANCHOR_AT);
        block
    }

    /// Primary body: zeroes past the tag.
    fn primary(lbn: u32) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        stamp_tag(&mut block, 1, (SIZE - 16) as u16, lbn);
        block
    }

    /// Partition body for number 0 at `PART_AT`, contents `+NSR03`.
    fn partition(lbn: u32) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        block[22..24].copy_from_slice(&0u16.to_le_bytes());
        block[25..31].copy_from_slice(b"+NSR03");
        block[188..192].copy_from_slice(&PART_AT.to_le_bytes());
        block[192..196].copy_from_slice(&900u32.to_le_bytes());
        stamp_tag(&mut block, 5, (SIZE - 16) as u16, lbn);
        block
    }

    /// Logical volume body: label `LABEL`, revision 2.01, one type-1 map
    /// to partition 0, file set at partition-relative block `fsd`.
    fn logical(lbn: u32, fsd: u32) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        block[84] = 8;
        block[85..90].copy_from_slice(b"LABEL");
        block[84 + 127] = 6;
        block[212..216].copy_from_slice(&SIZE.to_le_bytes());
        block[217..236].copy_from_slice(b"*OSTA UDF Compliant");
        block[240..242].copy_from_slice(&0x0201u16.to_le_bytes());
        block[248..252].copy_from_slice(&SIZE.to_le_bytes());
        block[252..256].copy_from_slice(&fsd.to_le_bytes());
        block[264..268].copy_from_slice(&6u32.to_le_bytes());
        block[268..272].copy_from_slice(&1u32.to_le_bytes());
        block[440..446].copy_from_slice(&[1, 6, 1, 0, 0, 0]);
        stamp_tag(&mut block, 6, (446 - 16) as u16, lbn);
        block
    }

    fn skipped(lbn: u32, id: u16) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        stamp_tag(&mut block, id, (SIZE - 16) as u16, lbn);
        block
    }

    fn terminator(lbn: u32) -> Vec<u8> {
        skipped(lbn, 8)
    }

    /// File set block at partition-relative `fsd_rel` with the root ICB
    /// (one block, `root_rel`, reference 0).
    fn fsd(fsd_rel: u32, root_rel: u32) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        block[400..404].copy_from_slice(&SIZE.to_le_bytes());
        block[404..408].copy_from_slice(&root_rel.to_le_bytes());
        stamp_tag(&mut block, 256, (SIZE - 16) as u16, fsd_rel);
        block
    }

    /// Extended file entry with `data` embedded (information length =
    /// data length), file type directory, claiming partition-relative
    /// `rel`.
    fn ext_entry(rel: u32, data: &[u8]) -> Vec<u8> {
        ext_typed_entry(rel, data, 4)
    }

    /// Extended file entry with `data` embedded and file type `ftype`.
    fn ext_typed_entry(rel: u32, data: &[u8], ftype: u8) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        block[27] = ftype;
        block[16 + 18..16 + 20].copy_from_slice(&3u16.to_le_bytes());
        block[56..64].copy_from_slice(&(data.len() as u64).to_le_bytes());
        block[208..212].copy_from_slice(&0u32.to_le_bytes());
        block[212..216].copy_from_slice(&(data.len() as u32).to_le_bytes());
        block[216..216 + data.len()].copy_from_slice(data);
        stamp_tag(&mut block, 266, (SIZE - 16) as u16, rel);
        block
    }

    /// Extended file entry with inline long allocation descriptors
    /// `(length, block)` (partition reference 0), information length
    /// `info`, file type `ftype`, claiming partition-relative `rel`.
    fn ext_long_entry(rel: u32, ads: &[(u32, u32)], info: u64, ftype: u8) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        block[27] = ftype;
        block[16 + 18..16 + 20].copy_from_slice(&1u16.to_le_bytes());
        block[56..64].copy_from_slice(&info.to_le_bytes());
        block[208..212].copy_from_slice(&0u32.to_le_bytes());
        block[212..216].copy_from_slice(&(ads.len() as u32 * 16).to_le_bytes());
        for (index, (len, lbn)) in ads.iter().enumerate() {
            let at = 216 + index * 16;
            block[at..at + 4].copy_from_slice(&len.to_le_bytes());
            block[at + 4..at + 8].copy_from_slice(&lbn.to_le_bytes());
        }
        stamp_tag(&mut block, 266, (SIZE - 16) as u16, rel);
        block
    }

    /// Raw data block holding `data` in its first bytes.
    fn data_block(data: &[u8]) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        block[..data.len()].copy_from_slice(data);
        block
    }

    /// One FID record: characteristics `char`, ICB (one block, `lbn`),
    /// `name` bytes, location `loc`, CRC fixed, padded to 4.
    fn fid_record(characteristics: u8, lbn: u32, name: &[u8], loc: u32) -> Vec<u8> {
        let body = 38 + name.len();
        let total = body + (4 - body % 4) % 4;
        let mut record = vec![0u8; total];
        record[16..18].copy_from_slice(&1u16.to_le_bytes());
        record[18] = characteristics;
        record[19] = name.len() as u8;
        record[20..24].copy_from_slice(&SIZE.to_le_bytes());
        record[24..28].copy_from_slice(&lbn.to_le_bytes());
        record[38..38 + name.len()].copy_from_slice(name);
        stamp_tag(&mut record, 257, (total - 16) as u16, loc);
        record
    }

    /// Full synthetic volume: recognition, anchor, six-descriptor main
    /// sequence (primary, logical with FSD at relative 8, partition,
    /// unallocated, implementation use, terminator), file set at absolute
    /// `PART_AT + 8` and root entry at `PART_AT + 10` embedding `root`.
    /// Layout sketch (512-byte blocks): anchor 256, main 96..104, FSD
    /// 265, root entry 267. Extra `(absolute block, bytes)` pairs land
    /// after the fixed layout; the store grows to hold them.
    fn full_volume(root: &[u8]) -> VecVolume {
        full_volume_with(root, &[])
    }

    fn full_volume_with(root: &[u8], extra: &[(u32, Vec<u8>)]) -> VecVolume {
        let fsd_rel = 8u32;
        let root_rel = 10u32;
        let mut total_blocks = PART_AT + 16;
        for (abs, _) in extra {
            total_blocks = total_blocks.max(abs.saturating_add(1));
        }
        let mut volume = VecVolume::new(u64::from(total_blocks) * u64::from(SIZE), 512)
            .expect("the fixture fits in RAM");
        let recognition = recognition(b"NSR03");
        volume
            .write_all_at(32768, &recognition)
            .expect("the recognition fits");
        let mut put = |abs: u32, bytes: &[u8]| {
            volume
                .write_all_at(u64::from(abs) * u64::from(SIZE), bytes)
                .expect("the block fits");
        };
        put(ANCHOR_AT, &anchor());
        put(96, &primary(96));
        put(97, &logical(97, fsd_rel));
        put(98, &partition(98));
        put(99, &skipped(99, 7));
        put(100, &skipped(100, 4));
        put(101, &terminator(101));
        put(PART_AT + fsd_rel, &fsd(fsd_rel, root_rel));
        put(PART_AT + root_rel, &ext_entry(root_rel, root));
        for (abs, bytes) in extra {
            put(*abs, bytes);
        }
        volume
    }

    /// Root data with a parent plus one file (`f.txt`, ICB at relative
    /// 11) and one subdirectory (`D`, ICB at relative 12), all located in
    /// the root block (relative 10).
    fn root_data() -> Vec<u8> {
        let mut data = fid_record(0x0A, 10, &[], 10);
        data.extend_from_slice(&fid_record(
            0x00,
            11,
            &[8, b'f', b'.', b't', b'x', b't'],
            10,
        ));
        data.extend_from_slice(&fid_record(0x02, 12, &[8, b'D'], 10));
        data
    }

    fn open_root(root: &[u8]) -> UdfReader {
        UdfReader::open(Box::new(full_volume(root))).expect("the synthetic volume opens")
    }

    #[test]
    fn open_reports_label_revision_nsr_and_blocks() {
        let reader = open_root(&root_data());
        assert_eq!(reader.volume_label(), "LABEL");
        assert_eq!(reader.udf_revision(), "2.01");
        assert_eq!(reader.nsr(), Nsr::Nsr03);
        assert_eq!(reader.block_size(), SIZE);
        assert_eq!(reader.partition_number(), 0);
        assert_eq!(reader.partition_start(), PART_AT);
        assert_eq!(reader.partition_length(), 900);
        assert_eq!(reader.fsd().root_icb.lbn, 10);
        assert_eq!(
            reader.total_bytes(),
            u64::from(PART_AT + 16) * u64::from(SIZE)
        );
    }

    #[test]
    fn root_listing_skips_the_parent() {
        let reader = open_root(&root_data());
        let root = reader.root();
        assert_eq!(root.name, "");
        assert!(root.is_directory);
        let entries = reader.read_dir(&root).expect("the root lists");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "f.txt");
        assert!(!entries[0].is_directory);
        assert_eq!(entries[0].icb.lbn, 11);
        assert_eq!(entries[0].file_version, 1);
        assert_eq!(entries[1].name, "D");
        assert!(entries[1].is_directory);
        assert_eq!(entries[1].icb.lbn, 12);
    }

    #[test]
    fn nsr02_opens_too() {
        let mut volume = full_volume(&root_data());
        let region = recognition(b"NSR02");
        volume
            .write_all_at(32768, &region)
            .expect("the NSR02 recognition fits");
        let reader = UdfReader::open(Box::new(volume)).expect("NSR02 opens");
        assert_eq!(reader.nsr(), Nsr::Nsr02);
    }

    #[test]
    fn bad_recognition_identifier_refuses() {
        let mut volume = full_volume(&root_data());
        let region = recognition(b"XXX01");
        volume
            .write_all_at(32768, &region)
            .expect("the bad recognition fits");
        let error = UdfReader::open(Box::new(volume)).expect_err("XXX01 refuses");
        let text = error.to_string();
        assert!(text.contains("34816"), "{text}");
        assert!(text.contains("XXX01"), "{text}");
    }

    #[test]
    fn short_store_refuses_before_any_parse() {
        let volume = VecVolume::new(100, 512).expect("100 bytes fit");
        let error = UdfReader::open(Box::new(volume)).expect_err("100 bytes refuse");
        let text = error.to_string();
        assert!(text.contains("38912"), "{text}");
    }

    #[test]
    fn compression_id_3_in_a_name_refuses() {
        let mut data = fid_record(0x0A, 10, &[], 10);
        data.extend_from_slice(&fid_record(0x00, 11, &[3, b'x'], 10));
        let reader = open_root(&data);
        let error = reader
            .read_dir(&reader.root())
            .expect_err("compression id 3 refuses");
        let text = error.to_string();
        assert!(text.contains('3'), "{text}");
        assert!(text.contains("offset"), "{text}");
    }

    #[test]
    fn resolve_icb_maps_through_the_partition() {
        let reader = open_root(&root_data());
        let icb = LongAd {
            extent_length: SIZE,
            lbn: 10,
            partition_ref: 0,
        };
        assert_eq!(
            reader.resolve_icb(&icb).expect("the ICB resolves"),
            (PART_AT + 10, SIZE)
        );
        let bad = LongAd {
            extent_length: SIZE,
            lbn: 10,
            partition_ref: 4,
        };
        let error = reader.resolve_icb(&bad).expect_err("reference 4 refuses");
        assert!(error.to_string().contains('4'), "{:?}", error);
    }

    /// Open a volume with `root` embedded in the root entry plus `extra`
    /// absolute blocks (file entries and data).
    fn open_with(root: &[u8], extra: &[(u32, Vec<u8>)]) -> UdfReader {
        UdfReader::open(Box::new(full_volume_with(root, extra))).expect("the volume opens")
    }

    /// Root data with a parent plus one embedded file (`f`, ICB at
    /// relative 11) and one empty file (`e`, ICB at relative 16).
    fn file_root() -> Vec<u8> {
        let mut data = fid_record(0x0A, 10, &[], 10);
        data.extend_from_slice(&fid_record(0x00, 11, &[8, b'f'], 10));
        data.extend_from_slice(&fid_record(0x00, 16, &[8, b'e'], 10));
        data
    }

    #[test]
    fn embedded_file_reads_and_seeks() {
        let reader = open_with(
            &file_root(),
            &[
                (PART_AT + 11, ext_typed_entry(11, b"hello udf", 5)),
                (PART_AT + 16, ext_typed_entry(16, b"", 5)),
            ],
        );
        let entries = reader.read_dir(&reader.root()).expect("the root lists");
        assert_eq!(entries.len(), 2);
        let file = reader.open_file(&entries[0]).expect("f opens");
        assert_eq!(file.len(), 9);
        assert!(!file.is_empty());
        assert_eq!(file.file_name(), "f");
        assert_eq!(reader.read_open(&file).expect("open reads"), b"hello udf");
        assert_eq!(
            reader.read_file(&entries[0]).expect("f reads"),
            b"hello udf"
        );
        let mut buf = [0u8; 4];
        let placed = reader
            .read_file_at(&entries[0], 0, &mut buf)
            .expect("offset 0 reads");
        assert_eq!(placed, 4);
        assert_eq!(&buf, b"hell");
        let placed = reader
            .read_file_at(&entries[0], 9, &mut buf)
            .expect("offset 9 is EOF");
        assert_eq!(placed, 0);
        let error = reader
            .read_file_at(&entries[0], 10, &mut buf)
            .expect_err("offset 10 past 9 refuses");
        let text = error.to_string();
        assert!(text.contains("10"), "{text}");
        assert!(text.contains('9'), "{text}");
        assert_eq!(reader.read_file(&entries[1]).expect("e reads"), b"");
        assert!(reader.open_file(&entries[1]).expect("e opens").is_empty());
    }

    #[test]
    fn extent_file_joins_across_blocks_and_cuts_to_length() {
        // One file as two 300-byte extents with information length 600
        // (exact join), one alias entry with length 500 (the tail never
        // reads).
        let mut root = fid_record(0x0A, 10, &[], 10);
        root.extend_from_slice(&fid_record(0x00, 13, &[8, b'b', b'i', b'g'], 10));
        root.extend_from_slice(&fid_record(0x00, 14, &[8, b'h', b'a', b'l', b'f'], 10));
        let first = vec![1u8; 300];
        let second = vec![2u8; 300];
        let reader = open_with(
            &root,
            &[
                (
                    PART_AT + 13,
                    ext_long_entry(13, &[(300, 20), (300, 21)], 600, 5),
                ),
                (
                    PART_AT + 14,
                    ext_long_entry(14, &[(300, 20), (300, 21)], 500, 5),
                ),
                (PART_AT + 20, data_block(&first)),
                (PART_AT + 21, data_block(&second)),
            ],
        );
        let entries = reader.read_dir(&reader.root()).expect("the root lists");
        assert_eq!(entries.len(), 2);
        let mut joined = vec![1u8; 300];
        joined.extend_from_slice(&vec![2u8; 300]);
        assert_eq!(reader.read_file(&entries[0]).expect("big reads"), joined);
        assert_eq!(
            reader.read_file(&entries[1]).expect("half reads"),
            joined[..500].to_vec()
        );
        let opened = reader.open_file(&entries[0]).expect("big opens");
        assert_eq!(opened.len(), 600);
        let mut buf = [0u8; 10];
        let placed = reader
            .read_open_at(&opened, 295, &mut buf)
            .expect("the straddle reads");
        assert_eq!(placed, 10);
        assert_eq!(&buf[..5], &[1u8; 5]);
        assert_eq!(&buf[5..], &[2u8; 5]);
    }

    #[test]
    fn directory_entry_refuses_file_reads_and_vice_versa() {
        let reader = open_with(
            &root_data(),
            &[(PART_AT + 11, ext_typed_entry(11, b"data", 5))],
        );
        let entries = reader.read_dir(&reader.root()).expect("the root lists");
        let error = reader
            .read_dir(&entries[0])
            .expect_err("a file never lists");
        let text = error.to_string();
        assert!(text.contains("f.txt"), "{text}");
        assert!(text.contains("not a directory"), "{text}");
        let error = reader
            .read_file(&reader.root())
            .expect_err("the root never reads as a file");
        assert!(error.to_string().contains("directory"), "{:?}", error);
    }

    #[test]
    fn symlink_and_fifo_refuse_with_their_kind() {
        let mut root = fid_record(0x0A, 10, &[], 10);
        root.extend_from_slice(&fid_record(0x00, 14, &[8, b'L'], 10));
        root.extend_from_slice(&fid_record(0x00, 15, &[8, b'F'], 10));
        let reader = open_with(
            &root,
            &[
                (PART_AT + 14, ext_typed_entry(14, b"\x05\x03link", 12)),
                (PART_AT + 15, ext_typed_entry(15, b"", 9)),
            ],
        );
        let entries = reader.read_dir(&reader.root()).expect("the root lists");
        assert_eq!(entries.len(), 2);
        let error = reader
            .read_file(&entries[0])
            .expect_err("a symlink never reads");
        assert!(error.to_string().contains("symbolic link"), "{:?}", error);
        let error = reader
            .read_file(&entries[1])
            .expect_err("a FIFO never reads");
        assert!(error.to_string().contains("FIFO"), "{:?}", error);
        let error = reader
            .read_dir(&entries[0])
            .expect_err("a symlink never lists");
        assert!(error.to_string().contains("symbolic link"), "{:?}", error);
        let fifo = reader
            .open_file(&entries[1])
            .expect_err("a FIFO never opens");
        assert!(fifo.to_string().contains("FIFO"), "{:?}", fifo);
    }

    #[test]
    fn other_file_types_refuse_with_their_kind() {
        // Socket (10), terminal (11), stream directory (13), block device
        // (6) and metadata main (250): every non-regular type refuses to
        // open with its kind named, and refuses to list as a directory.
        // Types 252-255 have no name table entry (see `file_type_name`)
        // and refuse as `unknown file type N`; 255 stands in for that
        // range here.
        let kinds: [(u8, &str, u8); 6] = [
            (10, "socket", b'S'),
            (11, "terminal", b'T'),
            (13, "stream directory", b'R'),
            (6, "block device", b'B'),
            (250, "metadata main", b'M'),
            (255, "unknown file type 255", b'U'),
        ];
        let mut root = fid_record(0x0A, 10, &[], 10);
        for (index, (_, _, tag)) in kinds.iter().enumerate() {
            let rel = 20 + index as u32;
            root.extend_from_slice(&fid_record(0x00, rel, &[8, *tag], 10));
        }
        let mut extra = Vec::new();
        for (index, (ftype, _, _)) in kinds.iter().enumerate() {
            let rel = 20 + index as u32;
            extra.push((PART_AT + rel, ext_typed_entry(rel, b"", *ftype)));
        }
        let reader = open_with(&root, &extra);
        let entries = reader.read_dir(&reader.root()).expect("the root lists");
        assert_eq!(entries.len(), kinds.len());
        for (entry, (_, want, _)) in entries.iter().zip(kinds.iter()) {
            let error = reader.open_file(entry).expect_err("never opens");
            assert!(error.to_string().contains(want), "{:?}", error);
            let error = reader.read_dir(entry).expect_err("never lists");
            assert!(error.to_string().contains(want), "{:?}", error);
        }
    }

    #[test]
    fn multi_extent_directory_lists_every_extent() {
        // D (relative 12) holds its identifiers in two extents sized to
        // the data: the parent plus a.txt live at relative 20, b.txt at
        // relative 21, joined contiguously before parsing.
        let mut root = fid_record(0x0A, 10, &[], 10);
        root.extend_from_slice(&fid_record(0x02, 12, &[8, b'D'], 10));
        let mut first = fid_record(0x0A, 12, &[], 20);
        first.extend_from_slice(&fid_record(0x00, 30, &[8, b'a'], 20));
        let second = fid_record(0x00, 31, &[8, b'b'], 21);
        let info = first.len() as u64 + second.len() as u64;
        let reader = open_with(
            &root,
            &[
                (
                    PART_AT + 12,
                    ext_long_entry(
                        12,
                        &[(first.len() as u32, 20), (second.len() as u32, 21)],
                        info,
                        4,
                    ),
                ),
                (PART_AT + 20, data_block(&first)),
                (PART_AT + 21, data_block(&second)),
            ],
        );
        let entries = reader.read_dir(&reader.root()).expect("the root lists");
        assert_eq!(entries.len(), 1);
        let listed = reader.read_dir(&entries[0]).expect("D lists both extents");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].name, "a");
        assert_eq!(listed[0].icb.lbn, 30);
        assert_eq!(listed[1].name, "b");
        assert_eq!(listed[1].icb.lbn, 31);
    }

    #[test]
    fn walk_lists_the_tree_with_absolute_paths() {
        // Root holds f (file) and D (directory holding inner).
        let mut root = fid_record(0x0A, 10, &[], 10);
        root.extend_from_slice(&fid_record(0x00, 11, &[8, b'f'], 10));
        root.extend_from_slice(&fid_record(0x02, 12, &[8, b'D'], 10));
        let mut sub = fid_record(0x0A, 12, &[], 12);
        sub.extend_from_slice(&fid_record(0x00, 15, &[8, b'i'], 12));
        let reader = open_with(
            &root,
            &[
                (PART_AT + 11, ext_typed_entry(11, b"hi", 5)),
                (PART_AT + 12, ext_typed_entry(12, &sub, 4)),
                (PART_AT + 15, ext_typed_entry(15, b"in", 5)),
            ],
        );
        let walked = reader.walk().expect("the tree walks");
        let paths: Vec<&str> = walked.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(paths, vec!["/", "/f", "/D", "/D/i"]);
        assert_eq!(walked[1].1.name, "f");
        assert!(!walked[1].1.is_directory);
        assert!(walked[2].1.is_directory);
        assert_eq!(walked[3].1.name, "i");
    }

    #[test]
    fn walk_refuses_a_directory_loop() {
        // L contains itself: every descent finds L again, so only the
        // depth bound stops the walk.
        let mut root = fid_record(0x0A, 10, &[], 10);
        root.extend_from_slice(&fid_record(0x02, 12, &[8, b'L'], 10));
        let mut looping = fid_record(0x0A, 12, &[], 12);
        looping.extend_from_slice(&fid_record(0x02, 12, &[8, b'L'], 12));
        let reader = open_with(&root, &[(PART_AT + 12, ext_typed_entry(12, &looping, 4))]);
        let error = reader.walk().expect_err("the loop refuses");
        assert!(error.to_string().contains("loop"), "{:?}", error);
    }

    #[test]
    fn hidden_lists_and_deleted_skips() {
        // h (0x01, hidden) lists; g (0x04, deleted) never appears even
        // though its record parses.
        let mut root = fid_record(0x0A, 10, &[], 10);
        root.extend_from_slice(&fid_record(0x01, 11, &[8, b'h'], 10));
        root.extend_from_slice(&fid_record(0x04, 12, &[8, b'g'], 10));
        let reader = open_with(
            &root,
            &[
                (PART_AT + 11, ext_typed_entry(11, b"hi", 5)),
                (PART_AT + 12, ext_typed_entry(12, b"gone", 5)),
            ],
        );
        let entries = reader.read_dir(&reader.root()).expect("the root lists");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "h");
    }

    #[test]
    fn corrupt_extent_type_names_the_file_and_index() {
        let mut root = fid_record(0x0A, 10, &[], 10);
        root.extend_from_slice(&fid_record(0x00, 13, &[8, b'b', b'a', b'd'], 10));
        let mut entry = ext_long_entry(13, &[(4, 20)], 4, 5);
        entry[216..220].copy_from_slice(&((1u32 << 30) | 4).to_le_bytes());
        stamp_tag(&mut entry, 266, (SIZE - 16) as u16, 13);
        let reader = open_with(&root, &[(PART_AT + 13, entry)]);
        let entries = reader.read_dir(&reader.root()).expect("the root lists");
        let error = reader.read_file(&entries[0]).expect_err("type 1 refuses");
        let text = error.to_string();
        assert!(text.contains("bad"), "{text}");
        assert!(text.contains("descriptor 0"), "{text}");
        assert!(text.contains("type 1"), "{text}");
    }

    #[test]
    fn escaping_extent_names_the_file_and_range() {
        // One block at relative 900 of a 900-block partition: the start
        // itself is past the end.
        let mut root = fid_record(0x0A, 10, &[], 10);
        root.extend_from_slice(&fid_record(0x00, 13, &[8, b'b', b'i', b'g'], 10));
        let reader = open_with(
            &root,
            &[(
                PART_AT + 13,
                ext_long_entry(13, &[(SIZE, 900)], SIZE as u64, 5),
            )],
        );
        let entries = reader.read_dir(&reader.root()).expect("the root lists");
        let error = reader
            .read_file(&entries[0])
            .expect_err("block 900 refuses");
        let text = error.to_string();
        assert!(text.contains("big"), "{text}");
        assert!(text.contains("900"), "{text}");
    }

    #[test]
    fn short_information_length_refuses() {
        let mut root = fid_record(0x0A, 10, &[], 10);
        root.extend_from_slice(&fid_record(0x00, 13, &[8, b's'], 10));
        let reader = open_with(
            &root,
            &[
                (PART_AT + 13, ext_long_entry(13, &[(4, 20)], 9, 5)),
                (PART_AT + 20, data_block(&[1, 2, 3, 4])),
            ],
        );
        let entries = reader.read_dir(&reader.root()).expect("the root lists");
        let error = reader
            .read_file(&entries[0])
            .expect_err("info 9 past 4 refuses");
        let text = error.to_string();
        assert!(text.contains('9'), "{text}");
        assert!(text.contains('4'), "{text}");
    }
}
