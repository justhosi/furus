//! El Torito boot catalog parsing (S14, slice 4 of 4).
//!
//! *Measured* — what `xorriso -as mkisofs -R -b boot.img -no-emul-boot
//! -boot-load-size 4 -V ETIMG` (version 1.5.8, inside `archlinux:latest`)
//! writes, byte-checked with `od` and pinned again by the synthetic
//! fixtures below: the catalog pointer is the 4-byte little-endian field
//! at bytes 71..75 of the type-0 boot record sector (byte 71 holds the
//! low byte; here `21 00 00 00` for LBA 33); the validation entry is
//! header id `0x01`, platform byte, two zero reserved bytes, a 24-byte
//! id string, the checksum word at bytes 28..30 (`0x55AA` here as a
//! little-endian word, balancing `0x0001` so the 16-word sum wraps to
//! zero), and the key bytes `0x55 0xAA` at bytes 30..32; the initial
//! entry is boot indicator `0x88`, media
//! `0x00` (no emulation), load segment `0x0000`, system type `0x00`,
//! sector count 4 (512-byte units), load RBA 34; the rest of the sector
//! is zero (no sections). Every refusal below is pinned synthetically.
//!
//! *Inferred* — the entry and section-header field order for kinds no
//! real image exercises (floppy media types, multi-section catalogs),
//! taken from the El Torito specification: the same 32-byte entry shape
//! as the measured initial entry, and section headers of id `0x90`
//! (more follow) / `0x91` (final) with platform byte, little-endian
//! entry count and 28-byte id string.
//!
//! Bounds, stated plainly: the catalog is read as whole sectors from the
//! catalog LBA, growing one sector at a time up to
//! [`MAX_BOOT_CATALOG_SECTORS`] sectors (real catalogs fit in one; the
//! cap only stops hostile entry counts from demanding the whole store).
//! A count reaching past the buffered catalog refuses, as does one
//! overlapping the next section header (entry slots starting with
//! `0x90`/`0x91` where an entry belongs). Every boot image window
//! (`load_rba * 2048`, `sector_count * 512`) is checked against the
//! store extent with checked arithmetic.
//!
//! Refusals, not panics: no boot record, a zero or out-of-store catalog
//! LBA, a wrong header id/key/checksum (the checksum names the expected
//! zero and the actual wrapped sum), a wrong boot indicator or media
//! type, an overflowing entry window, and an unreadable catalog sector
//! all refuse with the numbers named.

use crate::error::CoreError;
use crate::error::Result;
use crate::iso::SECTOR_BYTES;
use crate::iso::SECTOR_BYTES_U64;

/// Hard ceiling on catalog sectors read for one image: real catalogs
/// fit in one sector (validation entry, initial entry, a handful of
/// sections), so more than this means a hostile entry count, and one
/// catalog must not demand the whole store.
pub const MAX_BOOT_CATALOG_SECTORS: usize = 8;

/// One catalog entry is 32 bytes: every entry and section header shares
/// the length.
pub const BOOT_ENTRY_LEN: usize = 32;

/// Validation-entry header id: `0x01`.
const VALIDATION_ID: u8 = 0x01;
/// Validation-entry key, first byte at offset 30: `0x55`.
const VALIDATION_KEY_0: u8 = 0x55;
/// Validation-entry key, second byte at offset 31: `0xAA` (the key is
/// the on-disk byte pair `0x55 0xAA`, not a little-endian word).
const VALIDATION_KEY_1: u8 = 0xAA;
/// Section header id: more sections follow.
const SECTION_MORE: u8 = 0x90;
/// Section header id: the final section.
const SECTION_FINAL: u8 = 0x91;
/// Boot indicator: the entry is bootable.
const BOOTABLE: u8 = 0x88;
/// Boot indicator: the entry is not bootable.
const NOT_BOOTABLE: u8 = 0x00;
/// One boot image unit: entries count 512-byte sectors.
const IMAGE_UNIT_BYTES_U64: u64 = 512;

/// El Torito boot media (entry byte 1): how the BIOS loads the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    /// No emulation: the image loads as-is.
    NoEmulation,
    /// 1.2 MiB floppy emulation.
    Floppy12,
    /// 1.44 MiB floppy emulation.
    Floppy144,
    /// 2.88 MiB floppy emulation.
    Floppy288,
    /// Hard disk emulation.
    HardDisk,
}

/// One boot entry: the initial/default entry and every section entry
/// share this shape (boot indicator, media, load segment, system type,
/// sector count in 512-byte units, load RBA in 2048-byte sectors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootEntry {
    /// True for boot indicator `0x88`, false for `0x00`.
    pub bootable: bool,
    /// How the BIOS loads the image.
    pub media: MediaType,
    /// Load segment (`0x0000` loads at `0x7C0`).
    pub load_segment: u16,
    /// Partition-table system-type byte.
    pub system_type: u8,
    /// Image length in 512-byte sectors.
    pub sector_count: u16,
    /// Start of the boot image in 2048-byte sectors.
    pub load_rba: u32,
}

/// The validation entry: platform, id string, and the checksum that
/// proves the catalog (the key and the zero-sum are checked, not kept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationEntry {
    /// Platform id byte (`0x00` for 80x86 BIOS; kept raw, never
    /// interpreted).
    pub platform: u8,
    /// The 24-byte id string (trailing spaces and NULs trimmed,
    /// non-UTF-8 decoded lossily, like volume identifiers).
    pub id_string: String,
}

/// One catalog section: the entries under one `0x90`/`0x91` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSection {
    /// True for the final-section header id `0x91` (no sections follow).
    pub is_final: bool,
    /// Platform id byte, kept raw like the validation platform.
    pub platform: u8,
    /// The 28-byte section id string, decoded like the validation one.
    pub id_string: String,
    /// The section's boot entries in order.
    pub entries: Vec<BootEntry>,
}

/// The parsed boot catalog: the validation entry, the initial/default
/// entry, and every section in order (empty for the common
/// validation-plus-initial catalogs `xorriso` writes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootCatalog {
    /// The validation entry at catalog offset 0.
    pub validation: ValidationEntry,
    /// The initial/default entry at catalog offset 32.
    pub initial: BootEntry,
    /// The sections after it, in order.
    pub sections: Vec<BootSection>,
}

/// One byte at `at` in `bytes`, refused with the context when the
/// buffer ends first.
fn byte_at(bytes: &[u8], at: usize, what: &str) -> Result<u8> {
    bytes.get(at).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} ends before byte {at} of {} bytes",
            bytes.len()
        ))
    })
}

/// Little-endian 16-bit word at `at`, refused when the buffer ends
/// first.
fn le16(bytes: &[u8], at: usize, what: &str) -> Result<u16> {
    Ok(u16::from_le_bytes([
        byte_at(bytes, at, what)?,
        byte_at(bytes, at + 1, what)?,
    ]))
}

/// Little-endian 32-bit word at `at`, refused when the buffer ends
/// first.
fn le32(bytes: &[u8], at: usize, what: &str) -> Result<u32> {
    Ok(u32::from_le_bytes([
        byte_at(bytes, at, what)?,
        byte_at(bytes, at + 1, what)?,
        byte_at(bytes, at + 2, what)?,
        byte_at(bytes, at + 3, what)?,
    ]))
}

/// Raw id bytes to text: trailing spaces and NULs trimmed, non-UTF-8
/// decoded lossily — the same rule volume identifiers follow.
fn id_string(bytes: &[u8]) -> String {
    let mut trimmed = bytes;
    while trimmed.last() == Some(&b' ') || trimmed.last() == Some(&0) {
        match trimmed.get(..trimmed.len() - 1) {
            Some(rest) => trimmed = rest,
            None => break,
        }
    }
    String::from_utf8_lossy(trimmed).into_owned()
}

/// Media type byte to [`MediaType`]: 0-4 decode, anything else refuses
/// naming the value.
fn media_type(byte: u8) -> Result<MediaType> {
    match byte {
        0 => Ok(MediaType::NoEmulation),
        1 => Ok(MediaType::Floppy12),
        2 => Ok(MediaType::Floppy144),
        3 => Ok(MediaType::Floppy288),
        4 => Ok(MediaType::HardDisk),
        other => Err(CoreError::invalid(format!(
            "el torito boot entry has media type {other}, not 0 (no emulation), 1 (1.2M floppy), \
             2 (1.44M floppy), 3 (2.88M floppy) or 4 (hard disk)"
        ))),
    }
}

/// End offset of a section holding `count` entries at `cursor`:
/// `cursor + count * 32` with checked arithmetic, so a hostile count
/// refuses instead of wrapping.
fn section_end(cursor: usize, count: u16) -> Result<usize> {
    let entry_bytes = usize::from(count)
        .checked_mul(BOOT_ENTRY_LEN)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "el torito section of {count} entries overflows the byte arithmetic"
            ))
        })?;
    cursor.checked_add(entry_bytes).ok_or_else(|| {
        CoreError::invalid(format!(
            "el torito section of {count} entries at offset {cursor} overflows the byte arithmetic"
        ))
    })
}

/// Parse the validation entry at catalog offset 0: header id `0x01`,
/// zero reserved bytes, the id string, the `0x55AA` key, and the
/// checksum (the 16 little-endian words must sum to zero). Refuses a
/// wrong id, nonzero reserved bytes, a wrong key, and a wrong checksum
/// naming the expected zero and the actual wrapped sum.
fn parse_validation(buffer: &[u8]) -> Result<ValidationEntry> {
    let id = byte_at(buffer, 0, "el torito validation entry")?;
    if id != VALIDATION_ID {
        return Err(CoreError::invalid(format!(
            "el torito validation entry has header id {id}, not {VALIDATION_ID}"
        )));
    }
    let platform = byte_at(buffer, 1, "el torito validation entry")?;
    let reserved = le16(buffer, 2, "el torito validation entry")?;
    if reserved != 0 {
        return Err(CoreError::invalid(format!(
            "el torito validation entry has reserved bytes 0x{reserved:04x}, not zero"
        )));
    }
    let id_bytes = buffer.get(4..28).ok_or_else(|| {
        CoreError::invalid(format!(
            "el torito validation entry of {} bytes ends inside its id string",
            buffer.len()
        ))
    })?;
    let key_0 = byte_at(buffer, 30, "el torito validation entry")?;
    let key_1 = byte_at(buffer, 31, "el torito validation entry")?;
    if key_0 != VALIDATION_KEY_0 || key_1 != VALIDATION_KEY_1 {
        return Err(CoreError::invalid(format!(
            "el torito validation entry has key bytes 0x{key_0:02x} 0x{key_1:02x}, not 0x55 0xaa"
        )));
    }
    let mut sum: u32 = 0;
    for unit in 0..16 {
        let at = unit * 2;
        let word = u16::from_le_bytes([
            byte_at(buffer, at, "el torito validation entry")?,
            byte_at(buffer, at + 1, "el torito validation entry")?,
        ]);
        sum = sum.wrapping_add(u32::from(word));
    }
    let actual = (sum & 0xFFFF) as u16;
    if actual != 0 {
        return Err(CoreError::invalid(format!(
            "el torito validation entry has checksum 0x{actual:04x}, not 0x0000: \
             the 16 little-endian words must sum to zero"
        )));
    }
    Ok(ValidationEntry {
        platform,
        id_string: id_string(id_bytes),
    })
}

/// Parse one 32-byte boot entry at `at`: boot indicator `0x88`/`0x00`,
/// media type, load segment, system type, sector count (512-byte
/// units) and load RBA (2048-byte sectors). The image window must sit
/// inside `total_bytes`; a window running past the store refuses with
/// the numbers named.
fn parse_entry(buffer: &[u8], at: usize, total_bytes: u64) -> Result<BootEntry> {
    let indicator = byte_at(buffer, at, "el torito boot entry")?;
    let bootable = match indicator {
        BOOTABLE => true,
        NOT_BOOTABLE => false,
        other => {
            return Err(CoreError::invalid(format!(
                "el torito boot entry at offset {at} has boot indicator {other}, not 0 (not \
                 bootable) or 136 (bootable)"
            )));
        }
    };
    let media = media_type(byte_at(buffer, at + 1, "el torito boot entry")?)?;
    let load_segment = le16(buffer, at + 2, "el torito boot entry")?;
    let system_type = byte_at(buffer, at + 4, "el torito boot entry")?;
    let unused = byte_at(buffer, at + 5, "el torito boot entry")?;
    if unused != 0 {
        return Err(CoreError::invalid(format!(
            "el torito boot entry at offset {at} has unused byte {unused}, not zero"
        )));
    }
    let sector_count = le16(buffer, at + 6, "el torito boot entry")?;
    let load_rba = le32(buffer, at + 8, "el torito boot entry")?;
    let start = u64::from(load_rba)
        .checked_mul(SECTOR_BYTES_U64)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "el torito boot entry at offset {at} with load RBA {load_rba} overflows the byte \
                 offset arithmetic"
            ))
        })?;
    let length = u64::from(sector_count)
        .checked_mul(IMAGE_UNIT_BYTES_U64)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "el torito boot entry at offset {at} with sector count {sector_count} overflows \
                 the byte offset arithmetic"
            ))
        })?;
    let end = start.checked_add(length).ok_or_else(|| {
        CoreError::invalid(format!(
            "el torito boot entry at offset {at} with load RBA {load_rba} and sector count \
             {sector_count} overflows the byte offset arithmetic"
        ))
    })?;
    if end > total_bytes {
        return Err(CoreError::invalid(format!(
            "el torito boot entry at offset {at} of {sector_count} sectors at load RBA {load_rba} \
             spans bytes {start}..{end} past the {total_bytes} byte volume end"
        )));
    }
    Ok(BootEntry {
        bootable,
        media,
        load_segment,
        system_type,
        sector_count,
        load_rba,
    })
}

/// Grow `buffer` (sectors from `catalog_lba`) until `need` bytes are
/// present, one sector at a time up to [`MAX_BOOT_CATALOG_SECTORS`]:
/// unreadable sectors refuse with the sector named, and a need past
/// the cap refuses naming both numbers.
fn ensure(
    buffer: &mut Vec<u8>,
    read_sector: &mut dyn FnMut(u32) -> Result<[u8; SECTOR_BYTES]>,
    catalog_lba: u32,
    need: usize,
    what: &str,
) -> Result<()> {
    while buffer.len() < need {
        let have_sectors = buffer.len() / SECTOR_BYTES;
        if have_sectors >= MAX_BOOT_CATALOG_SECTORS {
            return Err(CoreError::invalid(format!(
                "el torito catalog needs {need} bytes for {what} but holds {} bytes after \
                 {MAX_BOOT_CATALOG_SECTORS} sectors: refusing an entry count that runs past \
                 the catalog",
                buffer.len()
            )));
        }
        let sector_no = catalog_lba.checked_add(have_sectors as u32).ok_or_else(|| {
            CoreError::invalid(format!(
                "el torito catalog at LBA {catalog_lba} plus sector {have_sectors} overflows the \
                 sector number"
            ))
        })?;
        let bytes = read_sector(sector_no).map_err(|error| {
            CoreError::invalid(format!(
                "el torito catalog sector {sector_no} is unreadable ({error})"
            ))
        })?;
        buffer.extend_from_slice(&bytes);
    }
    Ok(())
}

/// True when `buffer` from `at` on holds only zero bytes: trailing
/// padding past the last section (real catalogs zero the rest of the
/// sector).
fn rest_is_padding(buffer: &[u8], at: usize) -> bool {
    let mut index = at;
    while index < buffer.len() {
        match buffer.get(index) {
            Some(0) => index += 1,
            _ => return false,
        }
    }
    true
}

/// Parse the whole catalog at `catalog_lba` through whole-sector reads:
/// the validation entry, the initial entry, then section headers until
/// the final one. `total_bytes` bounds every boot image window.
pub fn parse_catalog(
    read_sector: &mut dyn FnMut(u32) -> Result<[u8; SECTOR_BYTES]>,
    total_bytes: u64,
    catalog_lba: u32,
) -> Result<BootCatalog> {
    if catalog_lba == 0 {
        return Err(CoreError::invalid(
            "el torito boot catalog LBA is zero: the boot record names no catalog",
        ));
    }
    let mut buffer = Vec::new();
    ensure(
        &mut buffer,
        read_sector,
        catalog_lba,
        BOOT_ENTRY_LEN,
        "the validation entry",
    )?;
    let validation = parse_validation(&buffer)?;
    ensure(
        &mut buffer,
        read_sector,
        catalog_lba,
        2 * BOOT_ENTRY_LEN,
        "the initial entry",
    )?;
    let initial = parse_entry(&buffer, BOOT_ENTRY_LEN, total_bytes)?;
    let mut sections = Vec::new();
    let mut at = 2 * BOOT_ENTRY_LEN;
    loop {
        let header_need = at.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "el torito section header at offset {at} overflows the byte arithmetic"
            ))
        })?;
        ensure(
            &mut buffer,
            read_sector,
            catalog_lba,
            header_need,
            "a section header",
        )?;
        if rest_is_padding(&buffer, at) {
            break;
        }
        let header_end = at.checked_add(BOOT_ENTRY_LEN).ok_or_else(|| {
            CoreError::invalid(format!(
                "el torito section header at offset {at} overflows the byte arithmetic"
            ))
        })?;
        ensure(
            &mut buffer,
            read_sector,
            catalog_lba,
            header_end,
            "a section header",
        )?;
        let id = byte_at(&buffer, at, "el torito section header")?;
        let is_final = match id {
            SECTION_MORE => false,
            SECTION_FINAL => true,
            other => {
                return Err(CoreError::invalid(format!(
                    "el torito section header at offset {at} has id {other}, not 144 (more \
                     sections follow) or 145 (final section)"
                )));
            }
        };
        let platform = byte_at(&buffer, at + 1, "el torito section header")?;
        let count = le16(&buffer, at + 2, "el torito section header")?;
        let id_start = at.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "el torito section header at offset {at} overflows the byte arithmetic"
            ))
        })?;
        let id_string = id_string(buffer.get(id_start..header_end).ok_or_else(|| {
            CoreError::invalid(format!(
                "el torito section header at offset {at} ends inside its id string"
            ))
        })?);
        let end = section_end(header_end, count)?;
        ensure(
            &mut buffer,
            read_sector,
            catalog_lba,
            end,
            "a section's entries",
        )?;
        let mut entries = Vec::new();
        for index in 0..count {
            let slot =
                at.checked_add(BOOT_ENTRY_LEN)
                    .ok_or_else(|| {
                        CoreError::invalid(format!(
                            "el torito section at offset {at} overflows the byte arithmetic"
                        ))
                    })?
                    .checked_add(usize::from(index).checked_mul(BOOT_ENTRY_LEN).ok_or_else(
                        || {
                            CoreError::invalid(format!(
                                "el torito section at offset {at} entry {index} overflows the byte \
                             arithmetic"
                            ))
                        },
                    )?)
                    .ok_or_else(|| {
                        CoreError::invalid(format!(
                            "el torito section at offset {at} entry {index} overflows the byte \
                         arithmetic"
                        ))
                    })?;
            let marker = byte_at(&buffer, slot, "el torito section entry")?;
            if marker == SECTION_MORE || marker == SECTION_FINAL {
                return Err(CoreError::invalid(format!(
                    "el torito section at offset {at} of {count} entries meets a section header \
                     id {marker} at entry {} (offset {slot}): refusing a count that overlaps \
                     the next section header",
                    index + 1
                )));
            }
            entries.push(parse_entry(&buffer, slot, total_bytes)?);
        }
        sections.push(BootSection {
            is_final,
            platform,
            id_string,
            entries,
        });
        at = end;
        if is_final {
            break;
        }
    }
    Ok(BootCatalog {
        validation,
        initial,
        sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Catalog LBA inside the test images (sector 2 of 40: the
    /// measured RBA-34 window needs the room).
    const TEST_CATALOG_LBA: u32 = 2;

    /// Whole-sector reads over `image`, refusing past the end. Test-only.
    fn sector_reader(image: &[u8]) -> impl FnMut(u32) -> Result<[u8; SECTOR_BYTES]> + '_ {
        move |sector: u32| {
            let start = sector as usize * SECTOR_BYTES;
            let window = image.get(start..start + SECTOR_BYTES).ok_or_else(|| {
                CoreError::invalid(format!("test sector {sector} is past the image end"))
            })?;
            let mut out = [0u8; SECTOR_BYTES];
            out.copy_from_slice(window);
            Ok(out)
        }
    }

    /// The measured validation entry: `01 00 0000`, 24 zero id bytes,
    /// checksum `AA 55`, key `55 AA` (the words sum to zero with the
    /// `0x0001` header word). Byte-copied from the `od` dump of the
    /// real catalog, not generated.
    fn validation_bytes() -> Vec<u8> {
        let mut out = vec![0x01, 0x00, 0x00, 0x00];
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&[0xAA, 0x55, 0x55, 0xAA]);
        out
    }

    /// Validation entry for `platform` with the 24-byte `id`, the
    /// checksum word computed so the 16 words sum to zero, and the key
    /// bytes `55 AA`. Fixture building only (the parser still verifies
    /// the sum); real catalogs with vendor ids look like this.
    /// Test-only.
    fn validation_for(platform: u8, id: &[u8]) -> Vec<u8> {
        let mut out = vec![0x01, platform, 0x00, 0x00];
        let mut field = vec![0u8; 24];
        let take = id.len().min(24);
        field[..take].copy_from_slice(&id[..take]);
        out.extend_from_slice(&field);
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&[0x55, 0xAA]);
        // Sum every word but the checksum slot itself (still zeroed),
        // key bytes included: the checksum balances the full 16 words.
        let mut sum: u32 = 0;
        for unit in 0..16 {
            sum += u32::from(u16::from_le_bytes([out[unit * 2], out[unit * 2 + 1]]));
        }
        let checksum = (0x1_0000 - (sum & 0xFFFF)) & 0xFFFF;
        out[28] = (checksum & 0xFF) as u8;
        out[29] = ((checksum >> 8) & 0xFF) as u8;
        out
    }

    /// The measured initial entry head: `88 00 0000 00 00 0400 22000000`
    /// (bootable, no emulation, segment 0, type 0, 4 sectors at RBA 34).
    /// Byte-copied from the `od` dump of the real catalog.
    fn initial_head() -> Vec<u8> {
        vec![
            0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x22, 0x00, 0x00, 0x00,
        ]
    }

    /// One 32-byte entry from a 12-byte head, zero tail. Test-only.
    fn entry_bytes(head: &[u8]) -> Vec<u8> {
        let mut out = head.to_vec();
        out.resize(BOOT_ENTRY_LEN, 0);
        out
    }

    /// One 32-byte section header: id, platform, LE count, 28-byte id.
    /// Test-only.
    fn header_bytes(id: u8, platform: u8, count: u16, name: &[u8]) -> Vec<u8> {
        let mut out = vec![id, platform, (count & 0xFF) as u8, (count >> 8) as u8];
        let mut id_field = vec![0u8; 28];
        let take = name.len().min(28);
        id_field[..take].copy_from_slice(&name[..take]);
        out.extend_from_slice(&id_field);
        out
    }

    /// Image of 40 zeroed sectors with `catalog` written at sector 2.
    /// Test-only.
    fn image_with_catalog(catalog: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; 40 * SECTOR_BYTES];
        let base = TEST_CATALOG_LBA as usize * SECTOR_BYTES;
        image[base..base + catalog.len()].copy_from_slice(catalog);
        image
    }

    /// Parse `catalog` (written at sector 2 of a 40-sector image)
    /// through [`parse_catalog`]. Test-only.
    fn parse(catalog: &[u8]) -> Result<BootCatalog> {
        let image = image_with_catalog(catalog);
        let total = image.len() as u64;
        let mut read = sector_reader(&image);
        parse_catalog(&mut read, total, TEST_CATALOG_LBA)
    }

    #[test]
    fn measured_catalog_parses() {
        let mut catalog = validation_bytes();
        catalog.extend_from_slice(&entry_bytes(&initial_head()));
        let parsed = parse(&catalog).expect("the measured catalog parses");
        assert_eq!(parsed.validation.platform, 0);
        assert_eq!(parsed.validation.id_string, "");
        assert_eq!(
            parsed.initial,
            BootEntry {
                bootable: true,
                media: MediaType::NoEmulation,
                load_segment: 0,
                system_type: 0,
                sector_count: 4,
                load_rba: 34,
            }
        );
        assert!(parsed.sections.is_empty());
    }

    #[test]
    fn checksum_refused_naming_expected_and_actual() {
        // Flip the checksum low byte at offset 28 from 0xAA to 0xAB:
        // the wrapped sum is 0x0001, not zero.
        let mut catalog = validation_bytes();
        catalog[28] = 0xAB;
        catalog.extend_from_slice(&entry_bytes(&initial_head()));
        let error = parse(&catalog).expect_err("the bad checksum refuses");
        let text = error.to_string();
        assert!(text.contains("0x0000"), "{text}");
        assert!(text.contains("0x0001"), "{text}");
    }

    #[test]
    fn wrong_key_refused() {
        // Flip the first key byte at offset 30 from 0x55 to 0x54.
        let mut catalog = validation_bytes();
        catalog[30] = 0x54;
        catalog.extend_from_slice(&entry_bytes(&initial_head()));
        let error = parse(&catalog).expect_err("the bad key refuses");
        let text = error.to_string();
        assert!(text.contains("0x54"), "{text}");
        assert!(text.contains("0x55 0xaa"), "{text}");
    }

    #[test]
    fn nonzero_vendor_id_accepted_with_id_surfaced() {
        // The case the inverted key read refused: a vendor id moves the
        // checksum word away from `0x55AA`, while the key bytes stay
        // `55 AA`.
        let mut catalog = validation_for(0, b"TEST VENDOR ID");
        catalog.extend_from_slice(&entry_bytes(&initial_head()));
        let parsed = parse(&catalog).expect("the vendor-id catalog parses");
        assert_eq!(parsed.validation.platform, 0);
        assert_eq!(parsed.validation.id_string, "TEST VENDOR ID");
        assert_eq!(parsed.initial.load_rba, 34);
    }

    #[test]
    fn nonzero_platform_accepted() {
        // PowerPC (1) and Mac (2) platforms with a vendor id: the
        // platform byte is surfaced raw, never interpreted.
        for platform in [1u8, 2u8] {
            let mut catalog = validation_for(platform, b"TEST VENDOR ID");
            catalog.extend_from_slice(&entry_bytes(&initial_head()));
            let parsed = parse(&catalog).expect("the platform catalog parses");
            assert_eq!(parsed.validation.platform, platform);
            assert_eq!(parsed.validation.id_string, "TEST VENDOR ID");
        }
    }

    #[test]
    fn nonzero_unused_entry_byte_refused() {
        // Entry byte 5 is unused and must read zero.
        let mut head = initial_head();
        head[5] = 0x01;
        let mut catalog = validation_bytes();
        catalog.extend_from_slice(&entry_bytes(&head));
        let error = parse(&catalog).expect_err("unused byte 1 refuses");
        let text = error.to_string();
        assert!(text.contains("unused byte 1"), "{text}");
    }

    #[test]
    fn wrong_header_id_and_reserved_refused() {
        let mut catalog = validation_bytes();
        catalog[0] = 0x02;
        catalog.extend_from_slice(&entry_bytes(&initial_head()));
        let error = parse(&catalog).expect_err("header id 2 refuses");
        let text = error.to_string();
        assert!(text.contains('2'), "{text}");
        assert!(text.contains('1'), "{text}");
        let mut catalog = validation_bytes();
        catalog[2] = 0x01;
        catalog.extend_from_slice(&entry_bytes(&initial_head()));
        let error = parse(&catalog).expect_err("nonzero reserved refuses");
        assert!(error.to_string().contains("0x0001"), "{error}");
    }

    #[test]
    fn every_media_type_decodes() {
        for (byte, media) in [
            (0, MediaType::NoEmulation),
            (1, MediaType::Floppy12),
            (2, MediaType::Floppy144),
            (3, MediaType::Floppy288),
            (4, MediaType::HardDisk),
        ] {
            let mut head = initial_head();
            head[1] = byte;
            let mut catalog = validation_bytes();
            catalog.extend_from_slice(&entry_bytes(&head));
            let parsed = parse(&catalog).expect("the media type parses");
            assert_eq!(parsed.initial.media, media, "media byte {byte}");
        }
        let mut head = initial_head();
        head[1] = 5;
        let mut catalog = validation_bytes();
        catalog.extend_from_slice(&entry_bytes(&head));
        let error = parse(&catalog).expect_err("media type 5 refuses");
        assert!(error.to_string().contains('5'), "{error}");
    }

    #[test]
    fn hard_disk_entry_pins_segment_count_and_rba() {
        // Non-bootable hard-disk entry: segment 0x07C0, type 0x06, 8
        // sectors at RBA 10.
        let head = vec![
            0x00, 0x04, 0xC0, 0x07, 0x06, 0x00, 0x08, 0x00, 0x0A, 0x00, 0x00, 0x00,
        ];
        let mut catalog = validation_bytes();
        catalog.extend_from_slice(&entry_bytes(&head));
        let parsed = parse(&catalog).expect("the hard-disk entry parses");
        assert_eq!(
            parsed.initial,
            BootEntry {
                bootable: false,
                media: MediaType::HardDisk,
                load_segment: 0x07C0,
                system_type: 0x06,
                sector_count: 8,
                load_rba: 10,
            }
        );
    }

    #[test]
    fn wrong_boot_indicator_refused() {
        let mut head = initial_head();
        head[0] = 0x01;
        let mut catalog = validation_bytes();
        catalog.extend_from_slice(&entry_bytes(&head));
        let error = parse(&catalog).expect_err("indicator 1 refuses");
        let text = error.to_string();
        assert!(text.contains('1'), "{text}");
        assert!(text.contains("136"), "{text}");
    }

    #[test]
    fn two_sections_with_a_final_header() {
        let first_entry = entry_bytes(&[
            0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00,
        ]);
        let second_entry = entry_bytes(&[
            0x88, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00,
        ]);
        let mut catalog = validation_bytes();
        catalog.extend_from_slice(&entry_bytes(&initial_head()));
        catalog.extend_from_slice(&header_bytes(0x90, 0, 1, b"first"));
        catalog.extend_from_slice(&first_entry);
        catalog.extend_from_slice(&header_bytes(0x91, 0, 1, b"second"));
        catalog.extend_from_slice(&second_entry);
        let parsed = parse(&catalog).expect("two sections parse");
        assert_eq!(parsed.sections.len(), 2);
        assert!(!parsed.sections[0].is_final);
        assert_eq!(parsed.sections[0].id_string, "first");
        assert_eq!(parsed.sections[0].entries.len(), 1);
        assert_eq!(parsed.sections[0].entries[0].media, MediaType::HardDisk);
        assert!(!parsed.sections[0].entries[0].bootable);
        assert!(parsed.sections[1].is_final);
        assert_eq!(parsed.sections[1].id_string, "second");
        assert_eq!(parsed.sections[1].entries[0].media, MediaType::Floppy144);
        assert!(parsed.sections[1].entries[0].bootable);
        assert_eq!(parsed.sections[1].entries[0].load_rba, 6);
    }

    #[test]
    fn section_count_overrunning_the_catalog_refused() {
        // 600 entries need 19264 bytes past the header: past the 8-sector
        // cap, so the count refuses without touching the store end.
        let mut catalog = validation_bytes();
        catalog.extend_from_slice(&entry_bytes(&initial_head()));
        catalog.extend_from_slice(&header_bytes(0x90, 0, 600, b"big"));
        let error = parse(&catalog).expect_err("the overrun refuses");
        let text = error.to_string();
        assert!(text.contains("runs past the catalog"), "{text}");
        assert!(text.contains('8'), "{text}");
    }

    #[test]
    fn section_end_overflow_refused() {
        let error = section_end(usize::MAX - 10, 1).expect_err("the sum overflows");
        assert!(error.to_string().contains("overflows"), "{error}");
        assert_eq!(
            section_end(64, 600).expect("small sums pass"),
            64 + 600 * BOOT_ENTRY_LEN
        );
    }

    #[test]
    fn count_overlapping_the_next_header_refused() {
        // Three entries claimed, but the second slot holds a final
        // section header: the count overlaps it and refuses.
        let entry = entry_bytes(&initial_head());
        let mut catalog = validation_bytes();
        catalog.extend_from_slice(&entry_bytes(&initial_head()));
        catalog.extend_from_slice(&header_bytes(0x90, 0, 3, b"over"));
        catalog.extend_from_slice(&entry);
        catalog.extend_from_slice(&header_bytes(0x91, 0, 0, b"next"));
        let error = parse(&catalog).expect_err("the overlap refuses");
        let text = error.to_string();
        assert!(text.contains("overlaps"), "{text}");
        assert!(text.contains("145"), "{text}");
    }

    #[test]
    fn image_window_past_the_store_refused() {
        // RBA 9999 (2048-byte sectors) runs far past the 40-sector image.
        let mut head = initial_head();
        head[8] = 0x0F;
        head[9] = 0x27;
        let mut catalog = validation_bytes();
        catalog.extend_from_slice(&entry_bytes(&head));
        let error = parse(&catalog).expect_err("the overrun refuses");
        let text = error.to_string();
        assert!(text.contains("past"), "{text}");
        assert!(text.contains("9999"), "{text}");
    }

    #[test]
    fn catalog_lba_zero_refused() {
        let image = image_with_catalog(&validation_bytes());
        let total = image.len() as u64;
        let mut read = sector_reader(&image);
        let error = parse_catalog(&mut read, total, 0).expect_err("LBA zero refuses");
        assert!(error.to_string().contains("zero"), "{error}");
    }

    #[test]
    fn unknown_section_header_id_refused() {
        let mut catalog = validation_bytes();
        catalog.extend_from_slice(&entry_bytes(&initial_head()));
        catalog.extend_from_slice(&header_bytes(0x92, 0, 0, b"bogus"));
        let error = parse(&catalog).expect_err("header id 0x92 refuses");
        let text = error.to_string();
        assert!(text.contains("146"), "{text}");
        assert!(text.contains("144"), "{text}");
    }
}
