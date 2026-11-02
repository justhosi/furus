//! qcow2 header validation, plus the logical reader.
//!
//! The header is big-endian: `QFI\xfb`, the version, the backing-file
//! offset and size, the cluster bits, the virtual size, then the L1
//! table offset and size. Layout facts come from the real `qemu-img
//! 11.1.3` `-f qcow2` image measured for this slice (version 3, no
//! backing file, 16 cluster bits, the 64 MiB size, one L1 entry at the
//! file end); the field order follows the qcow2 layout every producer
//! writes.
//!
//! The reader ([`Qcow2Reader`]) exposes the logical bytes as a
//! [`Volume`](crate::fs::Volume): each virtual cluster maps through
//! the L1 table to its L2 table and from there to its host cluster.
//!
//! *Measured* — `qemu-img 11.1.3` in `archlinux:latest`: a 64 MiB
//! `-f qcow2` conversion of a raw file reads back as the 67108864
//! byte virtual size, with 64 KiB clusters mapped through one L1
//! entry to an L2 table holding plain copied clusters (bit 63 set,
//! offset in bits 9..=55), byte-exact against `qemu-img convert
//! -O raw`. Markers written with `dd` into the raw at 0, 1 MiB,
//! 2 MiB, 32 MiB and the last 512 bytes all read back at their
//! virtual offsets.
//!
//! *Inferred* — the zero-flag shortcut (bit 0 set reads as zeros
//! without touching the host cluster: no producer on this host emits
//! a zero cluster with a backing host allocation, so the shortcut was
//! pinned only against synthetic entries) and the refusal of nonzero
//! reserved bits 1..=8 (QEMU masks them off, but a set bit there is
//! corruption this reader names rather than silently masking).

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;

use super::be_u32_at;
use super::be_u64_at;
use super::read_at;

/// Length of the version-2 header: every field this validator reads
/// sits inside it, so longer (version-3) headers need no wider read.
const HEADER_LEN: u64 = 72;
/// `QFI\xfb`, the magic.
const MAGIC: &[u8] = &[0x51, 0x46, 0x49, 0xFB];
/// Accepted versions (2, and 3 for the extended header).
const VERSION_2: u32 = 2;
/// Accepted versions (2, and 3 for the extended header).
const VERSION_3: u32 = 3;
/// Smallest cluster bits (512-byte clusters).
const MIN_CLUSTER_BITS: u32 = 9;
/// Largest cluster bits (2 MiB clusters).
const MAX_CLUSTER_BITS: u32 = 21;
/// Bytes per L1 entry.
const L1_ENTRY_LEN: u64 = 8;
/// Offset of the version.
const VERSION_AT: usize = 4;
/// Offset of the backing-file offset.
const BACKING_OFFSET_AT: usize = 8;
/// Offset of the backing-file size.
const BACKING_SIZE_AT: usize = 16;
/// Offset of the cluster bits.
const CLUSTER_BITS_AT: usize = 20;
/// Offset of the virtual size.
const SIZE_AT: usize = 24;
/// Offset of the L1 size (entry count).
const L1_SIZE_AT: usize = 36;
/// Offset of the L1 table offset.
const L1_OFFSET_AT: usize = 40;

/// Validate a file [`detect`](super::detect) committed to
/// [`ImageKind::Qcow2`](super::ImageKind::Qcow2): the magic, a version of 2 or 3, no backing
/// file (neither its offset nor an orphaned size), cluster bits within
/// 9..=21, a non-zero virtual size, and a non-empty L1 table whose
/// window sits inside the file.
pub(crate) fn validate(volume: &dyn Volume, total: u64) -> Result<()> {
    if total < HEADER_LEN {
        return Err(CoreError::invalid(format!(
            "qcow2 file of {total} bytes is shorter than the 72 byte header"
        )));
    }
    let header = read_at(volume, total, 0, HEADER_LEN, "qcow2 header")?;
    if !header.starts_with(MAGIC) {
        return Err(CoreError::invalid(
            "qcow2 magic is not QFI 0xfb: refusing a file the detector committed to qcow2",
        ));
    }
    let version = be_u32_at(&header, VERSION_AT, "qcow2 version")?;
    if version != VERSION_2 && version != VERSION_3 {
        return Err(CoreError::invalid(format!(
            "qcow2 version {version} is not 2 or 3"
        )));
    }
    let backing_offset = be_u64_at(&header, BACKING_OFFSET_AT, "qcow2 backing file offset")?;
    if backing_offset != 0 {
        return Err(CoreError::invalid(format!(
            "qcow2 backing file offset {backing_offset} is not zero: \
             external backing files are not supported"
        )));
    }
    let backing_size = be_u32_at(&header, BACKING_SIZE_AT, "qcow2 backing file size")?;
    if backing_size != 0 {
        return Err(CoreError::invalid(format!(
            "qcow2 backing file size {backing_size} is not zero while its offset is: \
             refusing an inconsistent header"
        )));
    }
    let cluster_bits = be_u32_at(&header, CLUSTER_BITS_AT, "qcow2 cluster bits")?;
    if !(MIN_CLUSTER_BITS..=MAX_CLUSTER_BITS).contains(&cluster_bits) {
        return Err(CoreError::invalid(format!(
            "qcow2 cluster bits {cluster_bits} is outside the 9..=21 range \
             (512 byte to 2 MiB clusters)"
        )));
    }
    let size = be_u64_at(&header, SIZE_AT, "qcow2 virtual size")?;
    if size == 0 {
        return Err(CoreError::invalid("qcow2 virtual size is zero"));
    }
    let l1_size = be_u32_at(&header, L1_SIZE_AT, "qcow2 L1 table size")?;
    if l1_size == 0 {
        return Err(CoreError::invalid("qcow2 L1 table size is zero"));
    }
    let l1_offset = be_u64_at(&header, L1_OFFSET_AT, "qcow2 L1 table offset")?;
    if l1_offset == 0 {
        return Err(CoreError::invalid(
            "qcow2 L1 table offset is zero: it would alias the header",
        ));
    }
    let table_len = u64::from(l1_size)
        .checked_mul(L1_ENTRY_LEN)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 L1 table of {l1_size} entries overflows the byte offset arithmetic"
            ))
        })?;
    let table_end = l1_offset.checked_add(table_len).ok_or_else(|| {
        CoreError::invalid(format!(
            "qcow2 L1 table of {table_len} bytes at offset {l1_offset} \
             overflows the byte offset arithmetic"
        ))
    })?;
    if table_end > total {
        return Err(CoreError::invalid(format!(
            "qcow2 L1 table of {table_len} bytes at offset {l1_offset} \
             (bytes {l1_offset}..{table_end}) runs past the {total} byte file end"
        )));
    }
    Ok(())
}

/// L2 table entry flag: the cluster reads as zeros without I/O.
const L2_ZERO: u64 = 1 << 0;
/// L2 table entry flag: the cluster payload is compressed (refused).
const L2_COMPRESSED: u64 = 1 << 62;
/// Host-cluster offset bits of an L1 or L2 entry (bits 9..=55): the
/// low 9 bits carry the zero flag plus reserved bits, the high bits
/// the allocation flags. Bit 63 (fully allocated) needs no special
/// handling on reads: the host cluster is followed either way, and
/// backing files (the only shape where it would matter) are refused
/// by [`validate`].
const ENTRY_OFFSET_MASK: u64 = 0x00_FFFF_FFFF_FE00;
/// Reserved low bits of an L2 entry (bits 1..=8): set bits are
/// corruption QEMU would silently mask, refused here by name.
const L2_RESERVED_MASK: u64 = 0x1FE;

/// The logical qcow2 volume: the file's virtual bytes as a read-only
/// [`Volume`].
///
/// Each virtual byte maps to its cluster (`offset / cluster_size`),
/// then through the L1 table (entry `cluster / l2_entries` points at
/// an L2 table) and the L2 table (entry `cluster % l2_entries`
/// points at the host cluster). An unmapped L2 table (a zero L1 entry
/// or one with no host offset) and an unallocated or zero-flagged L2
/// entry both read as zeros; a set compressed flag is refused naming
/// the guest offset and the raw entry. Every mapping is
/// bounds-checked before I/O with checked arithmetic. Tables are read
/// positionally on demand (8 bytes per entry): nothing is cached.
pub(crate) struct Qcow2Reader {
    file: Box<dyn Volume>,
    file_total: u64,
    virtual_size: u64,
    cluster_size: u64,
    l2_entries: u64,
    l1_offset: u64,
    l1_size: u32,
}

impl std::fmt::Debug for Qcow2Reader {
    /// The virtual size and the layout: the file itself has no useful
    /// textual shape (it is an open store), so it is not rendered.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Qcow2Reader")
            .field("virtual_size", &self.virtual_size)
            .field("cluster_size", &self.cluster_size)
            .field("l1_size", &self.l1_size)
            .finish_non_exhaustive()
    }
}

/// Header fields [`open`] needs beyond [`validate`].
struct Geometry {
    cluster_size: u64,
    virtual_size: u64,
    l1_offset: u64,
    l1_size: u32,
}

/// Re-read the validated header's geometry: the cluster size from
/// the cluster bits, the virtual size, and the L1 table offset and
/// size (whose window [`validate`] already proved inside the file).
fn read_geometry(file: &dyn Volume, total: u64) -> Result<Geometry> {
    let header = read_at(file, total, 0, HEADER_LEN, "qcow2 header")?;
    let cluster_bits = be_u32_at(&header, CLUSTER_BITS_AT, "qcow2 cluster bits")?;
    let cluster_size = 1u64.checked_shl(cluster_bits).ok_or_else(|| {
        CoreError::invalid(format!(
            "qcow2 cluster bits {cluster_bits} overflow the cluster size arithmetic"
        ))
    })?;
    let virtual_size = be_u64_at(&header, SIZE_AT, "qcow2 virtual size")?;
    let l1_size = be_u32_at(&header, L1_SIZE_AT, "qcow2 L1 table size")?;
    let l1_offset = be_u64_at(&header, L1_OFFSET_AT, "qcow2 L1 table offset")?;
    Ok(Geometry {
        cluster_size,
        virtual_size,
        l1_offset,
        l1_size,
    })
}

/// Open the validated qcow2 `file` (a `total` byte store [`validate`]
/// accepted) as its logical volume. An L1 table too small to cover
/// the virtual size is refused naming the size, the coverage and the
/// table length.
pub(crate) fn open(file: Box<dyn Volume>, total: u64) -> Result<Qcow2Reader> {
    validate(file.as_ref(), total)?;
    let geometry = read_geometry(file.as_ref(), total)?;
    let l2_entries = geometry
        .cluster_size
        .checked_div(L1_ENTRY_LEN)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 cluster size {} overflows the L2 entry count arithmetic",
                geometry.cluster_size
            ))
        })?;
    let l2_coverage = l2_entries
        .checked_mul(geometry.cluster_size)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 cluster size {} overflows the L2 coverage arithmetic",
                geometry.cluster_size
            ))
        })?;
    let required = geometry
        .virtual_size
        .checked_add(l2_coverage - 1)
        .and_then(|rounded| rounded.checked_div(l2_coverage))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 virtual size {} with {l2_coverage} byte L2 coverage \
                 overflows the L1 entry count arithmetic",
                geometry.virtual_size
            ))
        })?;
    if required > u64::from(geometry.l1_size) {
        return Err(CoreError::invalid(format!(
            "qcow2 virtual size {} needs {required} L1 entries for {l2_coverage} byte L2 \
             coverage but the header allows {}",
            geometry.virtual_size, geometry.l1_size
        )));
    }
    Ok(Qcow2Reader {
        file,
        file_total: total,
        virtual_size: geometry.virtual_size,
        cluster_size: geometry.cluster_size,
        l2_entries,
        l1_offset: geometry.l1_offset,
        l1_size: geometry.l1_size,
    })
}

/// Read one big-endian table entry: `index` counts in 8-byte entries
/// from `table_offset`, and an index past `table_len` entries is
/// refused naming the table, the index and the count before any I/O.
fn table_entry(
    file: &dyn Volume,
    file_total: u64,
    what: &str,
    table_offset: u64,
    table_len: u64,
    index: u64,
) -> Result<u64> {
    if index >= table_len {
        return Err(CoreError::invalid(format!(
            "qcow2 {what} entry {index} is past the {table_len} table entries"
        )));
    }
    let at = table_offset
        .checked_add(index.checked_mul(L1_ENTRY_LEN).ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 {what} entry {index} overflows the byte offset arithmetic"
            ))
        })?)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 {what} entry {index} at offset {table_offset} \
                 overflows the byte offset arithmetic"
            ))
        })?;
    let bytes = read_at(
        file,
        file_total,
        at,
        L1_ENTRY_LEN,
        &format!("qcow2 {what} entry"),
    )?;
    super::be_u64_at(&bytes, 0, &format!("qcow2 {what} entry"))
}

impl Qcow2Reader {
    /// Map one virtual span starting at `cur` (with `end` the read's
    /// end): the file offset (`None` reads as zeros) plus the span
    /// length, capped so the span never crosses a cluster boundary (a
    /// fresh L1/L2 lookup applies past it) nor `end`. A compressed
    /// cluster or set reserved bits are refused naming the guest
    /// offset and the raw entry.
    fn span(&self, cur: u64, end: u64) -> Result<(Option<u64>, u64)> {
        let cluster = cur.checked_div(self.cluster_size).ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 offset {cur} with {} byte clusters overflows the cluster number arithmetic",
                self.cluster_size
            ))
        })?;
        let base = cluster.checked_mul(self.cluster_size).ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 cluster {cluster} with {} byte clusters \
                 overflows the byte offset arithmetic",
                self.cluster_size
            ))
        })?;
        let within = cur.checked_sub(base).ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 offset {cur} runs before its cluster {cluster} base {base}"
            ))
        })?;
        let cluster_end = base.checked_add(self.cluster_size).ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 cluster {cluster} with {} byte clusters \
                 overflows the byte offset arithmetic",
                self.cluster_size
            ))
        })?;
        let left = cluster_end.checked_sub(cur).ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 offset {cur} runs past its cluster {cluster} end {cluster_end}"
            ))
        })?;
        let wanted = end.checked_sub(cur).ok_or_else(|| {
            CoreError::invalid(format!("qcow2 read position {cur} runs past its end {end}"))
        })?;
        let span = left.min(wanted);
        let l1_index = cluster.checked_div(self.l2_entries).ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 cluster {cluster} overflows the L1 index arithmetic"
            ))
        })?;
        let l1_entry = table_entry(
            self.file.as_ref(),
            self.file_total,
            "L1",
            self.l1_offset,
            u64::from(self.l1_size),
            l1_index,
        )?;
        let l2_base = l1_entry & ENTRY_OFFSET_MASK;
        if l2_base == 0 {
            return Ok((None, span));
        }
        let l2_index = cluster.checked_rem(self.l2_entries).ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 cluster {cluster} overflows the L2 index arithmetic"
            ))
        })?;
        let l2_table_len = self.l2_entries;
        let l2_end =
            l2_base.checked_add(l2_table_len.checked_mul(L1_ENTRY_LEN).ok_or_else(|| {
                CoreError::invalid(format!(
                    "qcow2 L2 table of {l2_table_len} entries overflows the byte offset arithmetic"
                ))
            })?);
        if l2_end.is_none_or(|end| end > self.file_total) {
            return Err(CoreError::invalid(format!(
                "qcow2 L2 table at offset {l2_base} runs past the {} byte file end",
                self.file_total
            )));
        }
        let l2_entry = table_entry(
            self.file.as_ref(),
            self.file_total,
            "L2",
            l2_base,
            self.l2_entries,
            l2_index,
        )?;
        if l2_entry & L2_COMPRESSED != 0 {
            return Err(CoreError::invalid(format!(
                "qcow2 guest offset {cur} L2 entry {l2_entry:#018x} is compressed: \
                 compressed clusters are not readable"
            )));
        }
        if l2_entry & L2_RESERVED_MASK != 0 {
            return Err(CoreError::invalid(format!(
                "qcow2 guest offset {cur} L2 entry {l2_entry:#018x} carries reserved bits: \
                 refusing a corrupt table"
            )));
        }
        if l2_entry & L2_ZERO != 0 {
            return Ok((None, span));
        }
        let host = l2_entry & ENTRY_OFFSET_MASK;
        if host == 0 {
            return Ok((None, span));
        }
        let file_off = host.checked_add(within).ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 guest offset {cur} host cluster {host:#x} at offset {within} \
                 overflows the byte offset arithmetic"
            ))
        })?;
        let span_end = file_off.checked_add(span).ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 guest offset {cur} read of {span} bytes at offset {file_off} \
                 overflows the byte offset arithmetic"
            ))
        })?;
        if span_end > self.file_total {
            return Err(CoreError::invalid(format!(
                "qcow2 guest offset {cur} host cluster (bytes {file_off}..{span_end}) runs past \
                 the {} byte file end",
                self.file_total
            )));
        }
        Ok((Some(file_off), span))
    }
}

impl Volume for Qcow2Reader {
    /// The virtual size from the header (without any L1, L2,
    /// refcount or data clusters: the 640 KiB file above holds a
    /// 64 MiB disk).
    fn total_bytes(&self) -> u64 {
        self.virtual_size
    }

    /// Fill `buf` from `offset`, mapping each span through the L1
    /// and L2 tables (allocated clusters read their payload,
    /// unallocated and zero clusters read as zeros). The window is
    /// bounds-checked against the virtual size before any I/O,
    /// naming the length, the offset and the virtual size; writes
    /// are refused.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let len = u64::try_from(buf.len()).map_err(|_| {
            CoreError::invalid("qcow2 read length does not fit the byte offset arithmetic")
        })?;
        let end = offset.checked_add(len).ok_or_else(|| {
            CoreError::invalid(format!(
                "qcow2 read of {len} bytes at offset {offset} overflows the byte offset arithmetic"
            ))
        })?;
        if end > self.virtual_size {
            return Err(CoreError::invalid(format!(
                "qcow2 read of {} bytes at offset {offset} runs past the {} byte virtual size",
                buf.len(),
                self.virtual_size
            )));
        }
        let mut done: usize = 0;
        let mut cur = offset;
        let total_len = buf.len();
        while cur < end {
            let (file_off, span) = self.span(cur, end)?;
            let count = usize::try_from(span).map_err(|_| {
                CoreError::invalid(format!(
                    "qcow2 read span {span} does not fit this machine's usize"
                ))
            })?;
            let window_end = done.checked_add(count).ok_or_else(|| {
                CoreError::invalid("qcow2 read position overflows the offset arithmetic")
            })?;
            if window_end > total_len {
                return Err(CoreError::invalid(format!(
                    "qcow2 read window {done}..{window_end} runs past the {total_len} byte buffer"
                )));
            }
            let dest = buf.get_mut(done..window_end).ok_or_else(|| {
                CoreError::invalid(format!(
                    "qcow2 read window {done}..{window_end} is not addressable"
                ))
            })?;
            match file_off {
                Some(at) => self.file.read_exact_at(at, dest)?,
                None => dest.fill(0),
            }
            done = done.checked_add(count).ok_or_else(|| {
                CoreError::invalid("qcow2 read position overflows the offset arithmetic")
            })?;
            cur = cur.checked_add(span).ok_or_else(|| {
                CoreError::invalid("qcow2 read position overflows the offset arithmetic")
            })?;
        }
        Ok(())
    }

    /// A qcow2 image is opened read-only: any write is refused naming
    /// the length and the offset, and the store is left untouched.
    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        Err(CoreError::invalid(format!(
            "refusing to write {} bytes at offset {offset}: a qcow2 image volume is read-only",
            buf.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;

    /// A well-formed header: version 3, no backing file, 16 cluster
    /// bits, a 64 MiB virtual size, one L1 entry.
    fn valid_header(l1_offset: u64) -> Vec<u8> {
        let mut header = vec![0u8; 72];
        header[0..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xFB]);
        header[4..8].copy_from_slice(&3u32.to_be_bytes());
        header[20..24].copy_from_slice(&16u32.to_be_bytes());
        header[24..32].copy_from_slice(&67_108_864u64.to_be_bytes());
        header[36..40].copy_from_slice(&1u32.to_be_bytes());
        header[40..48].copy_from_slice(&l1_offset.to_be_bytes());
        header
    }

    /// Validate `disk` through a memory volume of exactly that length.
    fn validate_disk(disk: &[u8]) -> Result<()> {
        let mut volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        volume.write_all_at(0, disk).expect("the fixture fits");
        validate(&volume, disk.len() as u64)
    }

    #[test]
    fn valid_header_with_l1_at_the_file_end_passes() {
        let l1_offset: u64 = 196_608;
        let mut disk = vec![0u8; 196_616];
        disk[0..72].copy_from_slice(&valid_header(l1_offset));
        validate_disk(&disk).expect("the well-formed header validates");
    }

    #[test]
    fn truncated_file_and_bad_magic_refuse() {
        let error = validate_disk(&[0x51, 0x46, 0x49, 0xFB]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("shorter than the 72 byte header")
        );

        let mut disk = vec![0u8; 196_616];
        let mut header = valid_header(196_608);
        header[0..4].copy_from_slice(b"QFI\xfa");
        disk[0..72].copy_from_slice(&header);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("not QFI"));
    }

    #[test]
    fn version_and_backing_file_and_cluster_bits_refuse() {
        for version in [1u32, 4u32] {
            let mut disk = vec![0u8; 196_616];
            let mut header = valid_header(196_608);
            header[4..8].copy_from_slice(&version.to_be_bytes());
            disk[0..72].copy_from_slice(&header);
            let error = validate_disk(&disk).unwrap_err();
            assert!(error.to_string().contains("is not 2 or 3"), "{error:?}");
        }

        let mut disk = vec![0u8; 196_616];
        let mut header = valid_header(196_608);
        header[8..16].copy_from_slice(&0x1000u64.to_be_bytes());
        disk[0..72].copy_from_slice(&header);
        let error = validate_disk(&disk).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("backing file offset 4096"), "{text}");

        let mut disk = vec![0u8; 196_616];
        let mut header = valid_header(196_608);
        header[16..20].copy_from_slice(&7u32.to_be_bytes());
        disk[0..72].copy_from_slice(&header);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("backing file size"));

        for bits in [8u32, 22u32] {
            let mut disk = vec![0u8; 196_616];
            let mut header = valid_header(196_608);
            header[20..24].copy_from_slice(&bits.to_be_bytes());
            disk[0..72].copy_from_slice(&header);
            let error = validate_disk(&disk).unwrap_err();
            assert!(
                error.to_string().contains("outside the 9..=21 range"),
                "{error:?}"
            );
        }
    }

    #[test]
    fn max_cluster_bits_boundary_accepts_21() {
        // 21 (2 MiB clusters) is the documented maximum: it validates
        // while 22 refuses (see the case above). Written as a literal
        // so lowering `MAX_CLUSTER_BITS` to 20 fails here.
        let mut disk = vec![0u8; 196_616];
        let mut header = valid_header(196_608);
        header[20..24].copy_from_slice(&21u32.to_be_bytes());
        disk[0..72].copy_from_slice(&header);
        validate_disk(&disk).expect("cluster bits 21 validate");
    }

    #[test]
    fn size_and_l1_refusals_name_their_field() {
        let mut disk = vec![0u8; 196_616];
        let mut header = valid_header(196_608);
        header[24..32].copy_from_slice(&0u64.to_be_bytes());
        disk[0..72].copy_from_slice(&header);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("virtual size is zero"));

        let mut disk = vec![0u8; 196_616];
        let mut header = valid_header(196_608);
        header[36..40].copy_from_slice(&0u32.to_be_bytes());
        disk[0..72].copy_from_slice(&header);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("L1 table size is zero"));

        let mut disk = vec![0u8; 196_616];
        disk[0..72].copy_from_slice(&valid_header(0));
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("L1 table offset is zero"));

        // The table claims one entry past the file end.
        let mut disk = vec![0u8; 196_616];
        disk[0..72].copy_from_slice(&valid_header(196_612));
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("runs past"));
    }

    /// A tiny readable disk: 512-byte clusters (9 cluster bits), one
    /// L2 table covering the 32768 byte virtual size, two stored
    /// clusters, one unallocated entry and one zero-flagged entry.
    const TINY_CLUSTER: u64 = 512;
    const TINY_VIRTUAL: u64 = 32_768;
    const TINY_L1: u64 = 512;
    const TINY_L2: u64 = 1024;
    const TINY_C0: u64 = 1536;
    const TINY_C1: u64 = 2048;
    const TINY_DISK: usize = 2560;

    /// The tiny disk above: L1[0] points at the L2 table, L2[0] and
    /// L2[1] are copied clusters, L2[2] is unallocated and L2[3]
    /// carries the zero flag.
    fn readable_disk() -> Vec<u8> {
        let mut disk = vec![0u8; TINY_DISK];
        disk[0..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xFB]);
        disk[4..8].copy_from_slice(&3u32.to_be_bytes());
        disk[20..24].copy_from_slice(&9u32.to_be_bytes());
        disk[24..32].copy_from_slice(&TINY_VIRTUAL.to_be_bytes());
        disk[36..40].copy_from_slice(&1u32.to_be_bytes());
        disk[40..48].copy_from_slice(&TINY_L1.to_be_bytes());
        disk[TINY_L1 as usize..TINY_L1 as usize + 8]
            .copy_from_slice(&(0x8000_0000_0000_0000u64 | TINY_L2).to_be_bytes());
        disk[TINY_L2 as usize..TINY_L2 as usize + 8]
            .copy_from_slice(&(0x8000_0000_0000_0000u64 | TINY_C0).to_be_bytes());
        disk[TINY_L2 as usize + 8..TINY_L2 as usize + 16]
            .copy_from_slice(&(0x8000_0000_0000_0000u64 | TINY_C1).to_be_bytes());
        disk[TINY_L2 as usize + 24..TINY_L2 as usize + 32].copy_from_slice(&L2_ZERO.to_be_bytes());
        disk[TINY_C0 as usize..TINY_C0 as usize + 16].copy_from_slice(b"QCOW2-CLUSTER0-M");
        disk[TINY_C1 as usize..TINY_C1 as usize + 16].copy_from_slice(b"QCOW2-CLUSTER1-M");
        disk[TINY_C0 as usize + 511] = 0x5A;
        disk
    }

    /// Open `disk` as its logical volume through a memory store.
    fn open_disk(disk: &[u8]) -> Qcow2Reader {
        let mut volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        volume.write_all_at(0, disk).expect("the fixture fits");
        open(Box::new(volume), disk.len() as u64).expect("the valid disk opens")
    }

    /// Open `disk` expecting refusal: the error, not the reader.
    fn open_disk_err(disk: &[u8]) -> CoreError {
        let mut volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        volume.write_all_at(0, disk).expect("the fixture fits");
        open(Box::new(volume), disk.len() as u64).expect_err("the corrupt disk refuses")
    }

    /// Read `len` bytes at `offset` from `reader`.
    fn read_from(reader: &Qcow2Reader, offset: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        reader
            .read_exact_at(offset, &mut out)
            .expect("the read fits");
        out
    }

    #[test]
    fn reader_maps_clusters_and_zeroes_holes() {
        let reader = open_disk(&readable_disk());
        assert_eq!(reader.total_bytes(), TINY_VIRTUAL);

        assert_eq!(&read_from(&reader, 0, 16), b"QCOW2-CLUSTER0-M");
        assert_eq!(&read_from(&reader, TINY_CLUSTER, 16), b"QCOW2-CLUSTER1-M");
        assert_eq!(read_from(&reader, 2 * TINY_CLUSTER, 512), vec![0u8; 512]);
        assert_eq!(read_from(&reader, 3 * TINY_CLUSTER, 512), vec![0u8; 512]);
        assert_eq!(read_from(&reader, 4 * TINY_CLUSTER, 64), vec![0u8; 64]);

        // A read may span a stored cluster and a hole: the last
        // payload byte first (0x5A at the cluster end), then zeros.
        let mut mixed = vec![0u8; 32];
        reader
            .read_exact_at(TINY_CLUSTER - 10, &mut mixed)
            .expect("the spanning read fits");
        assert!(mixed[..9].iter().all(|byte| *byte == 0));
        assert_eq!(mixed[9], 0x5A);
        assert_eq!(&mixed[10..26], b"QCOW2-CLUSTER1-M");
        assert!(mixed[26..].iter().all(|byte| *byte == 0));

        // A read ending exactly on the virtual size fits; one byte
        // past it names the length, the offset and the virtual size.
        read_from(&reader, TINY_VIRTUAL - 10, 10);
        let mut past = vec![0u8; 11];
        let error = reader
            .read_exact_at(TINY_VIRTUAL - 10, &mut past)
            .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("11 bytes"), "{text}");
        assert!(text.contains("virtual size"), "{text}");

        let mut reader = reader;
        let error = reader.write_all_at(0, b"x").unwrap_err();
        assert!(error.to_string().contains("read-only"), "{error:?}");
    }

    #[test]
    fn l2_mutants_refuse_or_read_zeros_and_restore_cleanly() {
        let pristine = readable_disk();

        // A compressed cluster is refused naming the guest offset
        // and the raw entry.
        let mut disk = pristine.clone();
        let at = TINY_L2 as usize;
        let entry = u64::from_be_bytes(disk[at..at + 8].try_into().expect("the entry is 8 bytes"));
        disk[at..at + 8].copy_from_slice(&(entry | L2_COMPRESSED).to_be_bytes());
        let reader = open_disk(&disk);
        let mut out = vec![0u8; 1];
        let error = reader.read_exact_at(0, &mut out).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("compressed"), "{text}");
        assert!(text.contains("guest offset 0"), "{text}");

        // Set reserved bits are refused naming the guest offset.
        let mut disk = pristine.clone();
        disk[at..at + 8].copy_from_slice(&(entry | 0x02).to_be_bytes());
        let reader = open_disk(&disk);
        let error = reader.read_exact_at(0, &mut out).unwrap_err();
        assert!(error.to_string().contains("reserved bits"));

        // A zero-flagged entry with a host cluster still reads as
        // zeros without I/O.
        let mut disk = pristine.clone();
        disk[at..at + 8].copy_from_slice(&(entry | L2_ZERO).to_be_bytes());
        let reader = open_disk(&disk);
        assert_eq!(read_from(&reader, 0, 16), vec![0u8; 16]);

        // An L1 entry with no host offset reads its whole L2
        // coverage as zeros.
        let mut disk = pristine.clone();
        let l1 = TINY_L1 as usize;
        disk[l1..l1 + 8].copy_from_slice(&0u64.to_be_bytes());
        let reader = open_disk(&disk);
        assert_eq!(read_from(&reader, 0, 64), vec![0u8; 64]);

        // An L2 table running past the file end is refused.
        let mut disk = pristine.clone();
        disk[l1..l1 + 8]
            .copy_from_slice(&(0x8000_0000_0000_0000u64 | 0x00_FFFF_FFFF_F000u64).to_be_bytes());
        let reader = open_disk(&disk);
        let error = reader.read_exact_at(0, &mut out).unwrap_err();
        assert!(error.to_string().contains("runs past"));

        // An L1 table too small for the virtual size refuses at open.
        let mut disk = pristine.clone();
        disk[24..32].copy_from_slice(&(2 * TINY_VIRTUAL).to_be_bytes());
        let error = open_disk_err(&disk);
        assert!(
            error.to_string().contains("needs 2 L1 entries"),
            "{error:?}"
        );

        assert_eq!(pristine, readable_disk(), "the mutants left no trace");
    }
}
