//! qcow2 header validation.
//!
//! The header is big-endian: `QFI\xfb`, the version, the backing-file
//! offset and size, the cluster bits, the virtual size, then the L1
//! table offset and size. Layout facts come from the real `qemu-img
//! 11.1.3` `-f qcow2` image measured for this slice (version 3, no
//! backing file, 16 cluster bits, the 64 MiB size, one L1 entry at the
//! file end); the field order follows the qcow2 layout every producer
//! writes.

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
}
