//! VHD footer and dynamic-header validation.
//!
//! The footer is the 512 bytes at size minus 512 (`conectix`, format
//! version, data offset, creator, sizes, geometry, disk type, checksum,
//! GUID); a dynamic disk continues at the footer's data offset with a
//! 1024-byte `cxsparse` header and its block allocation table. All
//! multi-byte fields are big-endian. Layout facts come from the two
//! `qemu-img 11.1.3` images measured for this slice (fixed and dynamic
//! `-f vpc` at 64 MiB); the interpretation of each field follows the
//! long-stable VHD layout every producer writes.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;

use super::be_u32_at;
use super::be_u64_at;
use super::read_at;
use super::window;

/// Length of the VHD footer in bytes.
const FOOTER_LEN: u64 = 512;
/// Length of the dynamic-disk header in bytes.
const DYN_HEADER_LEN: u64 = 1024;
/// `conectix`, the footer cookie.
const FOOTER_COOKIE: &[u8] = b"conectix";
/// `cxsparse`, the dynamic-header cookie.
const DYN_COOKIE: &[u8] = b"cxsparse";
/// The only file-format version the VHD layout defines (1.0).
const FORMAT_VERSION_1_0: u32 = 0x0001_0000;
/// Data offset of a fixed disk: no dynamic header follows.
const FIXED_DATA_OFFSET: u64 = 0xFFFF_FFFF_FFFF_FFFF;
/// Disk type of a fixed VHD.
const TYPE_FIXED: u32 = 2;
/// Disk type of a dynamic VHD.
const TYPE_DYNAMIC: u32 = 3;
/// Disk type of a differencing VHD (refused: it needs its parent).
const TYPE_DIFFERENCING: u32 = 4;
/// Bytes per BAT entry (one big-endian sector number each).
const BAT_ENTRY_LEN: u64 = 4;

/// Offset of the cookie within the footer.
const FOOTER_COOKIE_AT: usize = 0;
/// Offset of the file-format version within the footer.
const FOOTER_VERSION_AT: usize = 12;
/// Offset of the data offset within the footer.
const FOOTER_DATA_OFFSET_AT: usize = 16;
/// Offset of the creator application tag within the footer.
const FOOTER_CREATOR_AT: usize = 28;
/// Length of the creator application tag.
const FOOTER_CREATOR_LEN: usize = 4;
/// Offset of the current size within the footer.
const FOOTER_CURRENT_SIZE_AT: usize = 48;
/// Offset of the disk type within the footer.
const FOOTER_TYPE_AT: usize = 60;
/// Offset of the checksum within the footer.
const FOOTER_CHECKSUM_AT: usize = 64;

/// Offset of the BAT offset within the dynamic header.
const DYN_TABLE_OFFSET_AT: usize = 16;
/// Offset of the header version within the dynamic header.
const DYN_VERSION_AT: usize = 24;
/// Offset of the maximum BAT entry count within the dynamic header.
const DYN_MAX_ENTRIES_AT: usize = 28;
/// Offset of the block size within the dynamic header.
const DYN_BLOCK_SIZE_AT: usize = 32;
/// Offset of the checksum within the dynamic header.
const DYN_CHECKSUM_AT: usize = 36;

/// Validate a file [`detect`](super::detect) committed to
/// [`ImageKind::Vhd`](super::ImageKind::Vhd): the footer cookie, checksum, format version,
/// creator tag, disk type and size, plus the dynamic header and its
/// BAT window for dynamic disks.
///
/// Check order: cookie, checksum (untrusted bytes are not dispatched
/// on before they prove intact), format version, creator, disk type,
/// sizes, then the dynamic chain. Fixed (2) and dynamic (3) disks are
/// accepted; differencing (4) is refused for needing its parent image,
/// and any other type value is refused by number.
pub(crate) fn validate(volume: &dyn Volume, total: u64) -> Result<()> {
    if total < FOOTER_LEN {
        return Err(CoreError::invalid(format!(
            "vhd footer: file of {total} bytes is shorter than the 512 byte footer"
        )));
    }
    let base = total - FOOTER_LEN;
    let footer = read_at(volume, total, base, FOOTER_LEN, "vhd footer")?;
    let cookie = window(
        &footer,
        FOOTER_COOKIE_AT,
        FOOTER_COOKIE.len(),
        "vhd footer cookie",
    )?;
    if cookie != FOOTER_COOKIE {
        return Err(CoreError::invalid(
            "vhd footer cookie is not conectix: refusing a file the detector committed to VHD",
        ));
    }
    check_checksum(&footer, FOOTER_CHECKSUM_AT, "vhd footer")?;

    let version = be_u32_at(&footer, FOOTER_VERSION_AT, "vhd file format version")?;
    if version != FORMAT_VERSION_1_0 {
        return Err(CoreError::invalid(format!(
            "vhd file format version {version:#010x} is not 1.0 (0x00010000)"
        )));
    }

    let creator = window(
        &footer,
        FOOTER_CREATOR_AT,
        FOOTER_CREATOR_LEN,
        "vhd creator application",
    )?;
    if !creator.iter().all(|byte| (0x20..=0x7E).contains(byte)) {
        return Err(CoreError::invalid(
            "vhd creator application is not printable ASCII: refusing a corrupt footer",
        ));
    }

    let disk_type = be_u32_at(&footer, FOOTER_TYPE_AT, "vhd disk type")?;
    let current = be_u64_at(&footer, FOOTER_CURRENT_SIZE_AT, "vhd current size")?;
    if current == 0 {
        return Err(CoreError::invalid("vhd current size is zero"));
    }
    match disk_type {
        TYPE_FIXED => {
            // A fixed disk carries no dynamic header: its data offset
            // is all ones (the real `qemu-img -f vpc` fixed image reads
            // exactly that).
            let data_offset = be_u64_at(&footer, FOOTER_DATA_OFFSET_AT, "vhd data offset")?;
            if data_offset != FIXED_DATA_OFFSET {
                return Err(CoreError::invalid(format!(
                    "vhd fixed disk data offset {data_offset:#018x} is not all ones \
                     (no dynamic header follows a fixed disk)"
                )));
            }
            let want = current.checked_add(FOOTER_LEN).ok_or_else(|| {
                CoreError::invalid(format!(
                    "vhd fixed disk current size {current} overflows with the 512 byte footer"
                ))
            })?;
            if total != want {
                return Err(CoreError::invalid(format!(
                    "vhd fixed disk: file of {total} bytes is not the current size \
                     {current} plus the 512 byte footer"
                )));
            }
        }
        TYPE_DYNAMIC => {
            let data_offset = be_u64_at(&footer, FOOTER_DATA_OFFSET_AT, "vhd data offset")?;
            validate_dynamic(volume, total, current, data_offset)?;
        }
        TYPE_DIFFERENCING => {
            return Err(CoreError::invalid(
                "vhd disk type 4 (differencing): parent images are not readable standalone",
            ));
        }
        other => {
            return Err(CoreError::invalid(format!(
                "vhd disk type {other} is not fixed (2) or dynamic (3)"
            )));
        }
    }
    Ok(())
}

/// Validate the dynamic header at `data_offset` of a disk whose footer
/// promised `current` bytes: the `cxsparse` cookie, the checksum, the
/// header version, a non-zero block size and table count, a BAT window
/// inside the file, and a table large enough to cover the disk
/// (`ceil(current / block_size)` entries).
fn validate_dynamic(volume: &dyn Volume, total: u64, current: u64, data_offset: u64) -> Result<()> {
    let header = read_at(
        volume,
        total,
        data_offset,
        DYN_HEADER_LEN,
        "vhd dynamic header",
    )?;
    if !header.starts_with(DYN_COOKIE) {
        return Err(CoreError::invalid(
            "vhd dynamic header cookie is not cxsparse: refusing a corrupt dynamic disk",
        ));
    }
    check_checksum(&header, DYN_CHECKSUM_AT, "vhd dynamic header")?;

    let version = be_u32_at(&header, DYN_VERSION_AT, "vhd dynamic header version")?;
    if version != FORMAT_VERSION_1_0 {
        return Err(CoreError::invalid(format!(
            "vhd dynamic header version {version:#010x} is not 1.0 (0x00010000)"
        )));
    }

    let block_size = be_u32_at(&header, DYN_BLOCK_SIZE_AT, "vhd dynamic header block size")?;
    if block_size == 0 {
        return Err(CoreError::invalid("vhd dynamic header block size is zero"));
    }
    let max_entries = be_u32_at(&header, DYN_MAX_ENTRIES_AT, "vhd maximum table entries")?;
    if max_entries == 0 {
        return Err(CoreError::invalid("vhd maximum table entries is zero"));
    }
    let table_offset = be_u64_at(&header, DYN_TABLE_OFFSET_AT, "vhd table offset")?;
    if table_offset == 0 {
        return Err(CoreError::invalid(
            "vhd table offset is zero: it would alias the footer copy dynamic disks carry at 0",
        ));
    }
    let table_len = u64::from(max_entries)
        .checked_mul(BAT_ENTRY_LEN)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhd block table of {max_entries} entries overflows the byte offset arithmetic"
            ))
        })?;
    let table_end = table_offset.checked_add(table_len).ok_or_else(|| {
        CoreError::invalid(format!(
            "vhd block table of {table_len} bytes at offset {table_offset} \
             overflows the byte offset arithmetic"
        ))
    })?;
    if table_end > total {
        return Err(CoreError::invalid(format!(
            "vhd block table of {table_len} bytes at offset {table_offset} \
             (bytes {table_offset}..{table_end}) runs past the {total} byte file end"
        )));
    }
    let block = u64::from(block_size);
    let required = current
        .checked_add(block - 1)
        .and_then(|rounded| rounded.checked_div(block))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhd current size {current} with {block} byte blocks overflows the block count arithmetic"
            ))
        })?;
    if required > u64::from(max_entries) {
        return Err(CoreError::invalid(format!(
            "vhd current size {current} needs {required} block table entries for {block} byte \
             blocks but the header allows {max_entries}"
        )));
    }
    Ok(())
}

/// Check the one's-complement checksum stored at `at` of a `len`-byte
/// header: the stored value must equal the bitwise negation of the sum
/// of every other byte. The sum of at most 1024 bytes below 256 each
/// stays far below `u32::MAX`, so the `u32` accumulation cannot
/// overflow (512 times 255 is 130560).
fn check_checksum(header: &[u8], at: usize, what: &str) -> Result<()> {
    let stored = be_u32_at(header, at, &format!("{what} checksum"))?;
    let mut sum: u32 = 0;
    for (index, byte) in header.iter().enumerate() {
        if index < at || index >= at + 4 {
            sum += u32::from(*byte);
        }
    }
    let computed = !sum;
    if stored != computed {
        return Err(CoreError::invalid(format!(
            "{what} checksum mismatch: stored {stored:08x} against computed {computed:08x}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;

    /// Footer field offsets shared with the fixtures.
    const FOOTER_SIZE: usize = 512;

    /// A well-formed fixed-disk footer for a `total` byte file whose
    /// virtual size is `total - 512`, checksum fixed.
    fn fixed_footer(total: u64) -> Vec<u8> {
        let mut footer = vec![0u8; FOOTER_SIZE];
        footer[0..8].copy_from_slice(b"conectix");
        footer[8..12].copy_from_slice(&2u32.to_be_bytes());
        footer[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        footer[16..24].copy_from_slice(&FIXED_DATA_OFFSET.to_be_bytes());
        footer[24..28].copy_from_slice(&0x327Bu32.to_be_bytes());
        footer[28..32].copy_from_slice(b"qemu");
        footer[32..36].copy_from_slice(&0x0005_0003u32.to_be_bytes());
        footer[36..40].copy_from_slice(b"Wi2k");
        let current = total - 512;
        footer[40..48].copy_from_slice(&current.to_be_bytes());
        footer[48..56].copy_from_slice(&current.to_be_bytes());
        footer[56..60].copy_from_slice(&[0x03, 0xC4, 0x08, 0x11]);
        footer[60..64].copy_from_slice(&TYPE_FIXED.to_be_bytes());
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);
        footer
    }

    /// Fix the one's-complement checksum at `at` of `header`.
    fn stamp_checksum(header: &mut [u8], at: usize) {
        let mut sum: u32 = 0;
        for (index, byte) in header.iter().enumerate() {
            if index < at || index >= at + 4 {
                sum += u32::from(*byte);
            }
        }
        header[at..at + 4].copy_from_slice(&(!sum).to_be_bytes());
    }

    /// A well-formed dynamic disk: footer copy, dynamic header, BAT,
    /// footer; `current` virtual bytes in `block_size` byte blocks.
    fn dynamic_disk(current: u64, block_size: u32) -> Vec<u8> {
        let max_entries = current.div_ceil(u64::from(block_size)) as u32;
        let table_offset: u64 = 1536;
        let data_offset: u64 = 512;
        let mut header = vec![0u8; 1024];
        header[0..8].copy_from_slice(b"cxsparse");
        header[8..16].copy_from_slice(&FIXED_DATA_OFFSET.to_be_bytes());
        header[16..24].copy_from_slice(&table_offset.to_be_bytes());
        header[24..28].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        header[28..32].copy_from_slice(&max_entries.to_be_bytes());
        header[32..36].copy_from_slice(&block_size.to_be_bytes());
        stamp_checksum(&mut header, DYN_CHECKSUM_AT);

        let mut footer = vec![0u8; FOOTER_SIZE];
        footer[0..8].copy_from_slice(b"conectix");
        footer[8..12].copy_from_slice(&2u32.to_be_bytes());
        footer[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        footer[16..24].copy_from_slice(&data_offset.to_be_bytes());
        footer[28..32].copy_from_slice(b"qemu");
        footer[32..36].copy_from_slice(&0x0005_0003u32.to_be_bytes());
        footer[36..40].copy_from_slice(b"Wi2k");
        footer[40..48].copy_from_slice(&current.to_be_bytes());
        footer[48..56].copy_from_slice(&current.to_be_bytes());
        footer[60..64].copy_from_slice(&TYPE_DYNAMIC.to_be_bytes());
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);

        let bat_len = max_entries as usize * 4;
        let total = (table_offset + bat_len as u64).div_ceil(512) * 512 + 512;
        let mut disk = vec![0xFFu8; total as usize];
        disk[0..512].copy_from_slice(&footer);
        disk[512..1536].copy_from_slice(&header);
        let end = (total - 512) as usize;
        disk[end..end + 512].copy_from_slice(&footer);
        disk
    }

    /// Validate `disk` through a memory volume of exactly that length.
    fn validate_disk(disk: &[u8]) -> Result<()> {
        let mut volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        volume.write_all_at(0, disk).expect("the fixture fits");
        validate(&volume, disk.len() as u64)
    }

    #[test]
    fn valid_fixed_and_dynamic_disks_pass() {
        let total: u64 = 67_125_248 + 512;
        let mut disk = vec![0u8; total as usize];
        let footer = fixed_footer(total);
        disk[total as usize - 512..].copy_from_slice(&footer);
        validate_disk(&disk).expect("the fixed disk validates");

        let dynamic = dynamic_disk(67_125_248, 2_097_152);
        validate_disk(&dynamic).expect("the dynamic disk validates");
    }

    #[test]
    fn truncated_footer_and_bad_cookie_refuse() {
        let volume = VecVolume::new(511, 512).expect("the RAM");
        let error = validate(&volume, 511).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("shorter than the 512 byte footer")
        );

        let mut disk = vec![0u8; 1024];
        disk[512..520].copy_from_slice(b"conectiy");
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("not conectix"));
    }

    #[test]
    fn bad_footer_checksum_refuses_naming_both_values() {
        let total: u64 = 4096 + 512;
        let mut disk = vec![0u8; total as usize];
        let mut footer = fixed_footer(total);
        footer[100] ^= 0x01;
        disk[total as usize - 512..].copy_from_slice(&footer);
        let error = validate_disk(&disk).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("checksum mismatch"), "{text}");
        assert!(text.contains("stored"), "{text}");
        assert!(text.contains("computed"), "{text}");
    }

    #[test]
    fn wrong_version_and_creator_and_type_refuse() {
        let total: u64 = 4096 + 512;
        let mut footer = fixed_footer(total);
        footer[12..16].copy_from_slice(&0x0002_0000u32.to_be_bytes());
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);
        let mut disk = vec![0u8; total as usize];
        disk[total as usize - 512..].copy_from_slice(&footer);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("format version"));

        let mut footer = fixed_footer(total);
        footer[28..32].copy_from_slice(&[0xFF, 0x00, b'a', b'b']);
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);
        disk[total as usize - 512..].copy_from_slice(&footer);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("creator application"));

        for (disk_type, phrase) in [(TYPE_DIFFERENCING, "differencing"), (7u32, "not fixed")] {
            let mut footer = fixed_footer(total);
            footer[60..64].copy_from_slice(&disk_type.to_be_bytes());
            stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);
            disk[total as usize - 512..].copy_from_slice(&footer);
            let error = validate_disk(&disk).unwrap_err();
            assert!(error.to_string().contains(phrase), "{error:?}");
        }
    }

    #[test]
    fn fixed_size_mismatch_and_zero_current_size_refuse() {
        let total: u64 = 4096 + 512;
        let footer = fixed_footer(total + 512);
        let mut disk = vec![0u8; total as usize];
        disk[total as usize - 512..].copy_from_slice(&footer);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("plus the 512 byte footer"));

        let mut footer = fixed_footer(total);
        footer[48..56].copy_from_slice(&0u64.to_be_bytes());
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);
        disk[total as usize - 512..].copy_from_slice(&footer);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("current size is zero"));

        // A fixed disk pointing at a dynamic header is corrupt: the
        // data offset must stay all ones.
        let mut footer = fixed_footer(total);
        footer[16..24].copy_from_slice(&512u64.to_be_bytes());
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);
        disk[total as usize - 512..].copy_from_slice(&footer);
        let error = validate_disk(&disk).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("data offset"), "{text}");
        assert!(text.contains("all ones"), "{text}");
    }

    #[test]
    fn dynamic_chain_refusals_name_their_field() {
        // Bad dynamic checksum: flip a reserved byte, keep the cookie.
        let mut dynamic = dynamic_disk(1_048_576, 2_097_152);
        dynamic[600] ^= 0x40;
        let error = validate_disk(&dynamic).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("dynamic header checksum mismatch")
        );

        // Truncated dynamic header: point the data offset 100 bytes
        // before the file end so its 1024-byte window overruns.
        let mut cut = dynamic_disk(1_048_576, 2_097_152);
        let total = cut.len() as u64;
        let end = cut.len() - 512;
        cut[end + 16..end + 24].copy_from_slice(&(total - 100).to_be_bytes());
        stamp_checksum(&mut cut[end..end + 512], FOOTER_CHECKSUM_AT);
        let error = validate_disk(&cut).unwrap_err();
        assert!(error.to_string().contains("dynamic header"));

        // Table too small for the virtual size: claim one entry for a
        // two-block disk.
        let mut small = dynamic_disk(2 * 2_097_152, 2_097_152);
        small[512 + 28..512 + 32].copy_from_slice(&1u32.to_be_bytes());
        stamp_checksum(&mut small[512..1536], DYN_CHECKSUM_AT);
        let error = validate_disk(&small).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("needs 2 block table entries"), "{text}");
    }
}
