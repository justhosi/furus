//! Upstream SYSLINUX `syslinux_patch` plus the default ADV buffer.
//!
//! The loader cannot boot from a raw payload: the core carries a patch
//! area (found by scanning for [`LDLINUX_MAGIC`]) whose sector map,
//! sector pointers, ADV pointers, directory string and checksum must
//! match the file's on-disk layout, and the VBR carries two sector
//! pointers at the core's EPA offsets that must name the file's first
//! sector. [`syslinux_patch`] performs every write upstream's
//! `libinstaller/syslxmod.c` does, in its order, over explicit bytes;
//! [`default_adv`] builds the 1024-byte ADV tail upstream's
//! `setadv.c:syslinux_reset_adv` writes. No I/O here: the caller lays
//! the returned bytes down (see [`install_payloads`](super::install_payloads)).
//!
//! All integers are little-endian and every offset is an absolute file
//! offset into the core payload, exactly like upstream.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::fat32::put_bytes;
use crate::fs::fat32::put_u16;
use crate::fs::fat32::put_u32;

/// Magic dword a Syslinux core carries at file offset `0x18`
/// (`LDLINUX_MAGIC` in `syslxint.h`).
pub const LDLINUX_MAGIC: u32 = 0x3eb2_02fe;

/// File offset of the magic in both embedded assets; the scan starts
/// at dword 0 and takes the first match (see [`syslinux_patch`]).
pub const MAGIC_OFFSET: usize = 0x18;

/// Sector size every length below counts in: the ADV unit, the
/// `adv_sectors` count and the sector-pointer LBAs are all 512-byte
/// sectors, so the installer refuses any other volume sector size
/// before calling here.
pub const SECTOR_BYTES: u64 = 512;

/// ADV sectors appended after the core (`adv_sectors` is always 2).
pub const ADV_SECTORS: u64 = 2;

/// ADV tail length in bytes (`2 * 512`).
pub const ADV_BYTES: usize = 1024;

/// Per-sector ADV lead magic (`ADV_MAGIC1` in `setadv.c`).
pub const ADV_MAGIC_START: u32 = 0x5a2d_2fa5;

/// Per-sector ADV closing magic (`ADV_MAGIC2` in `setadv.c`).
pub const ADV_MAGIC_END: u32 = 0xdd28_bf64;

/// ADV checksum seed (`ADV_CSUM_SEED` in `setadv.c`): the stored
/// checksum is this minus the wrapping sum of the u32s at offsets 8,
/// 12, ... 504, which for the zeroed buffer is exactly the seed.
pub const ADV_CHECKSUM_SEED: u32 = 0xa304_1767;

/// Patch-area field offsets relative to the magic dword.
const DATA_SECTORS_AT: usize = 0x08;
const ADV_SECTORS_AT: usize = 0x0A;
const DWORDS_AT: usize = 0x0C;
const CHECKSUM_AT: usize = 0x10;
const EPA_OFFSET_AT: usize = 0x16;
/// Patch-area length past the magic: the `epaoffset` u16 at `+0x16`
/// closes the area, so a scan hit needs `0x18` bytes after it.
const PATCH_AREA_LEN: usize = 0x18;

/// EPA (extended patch area) entry indexes into the u16 array at
/// `epaoffset`.
const EPA_ADVPTR: usize = 0;
const EPA_DIR: usize = 1;
const EPA_DIRLEN: usize = 2;
const EPA_SECPTR: usize = 5;
const EPA_SECPTRCNT: usize = 6;
const EPA_SECT1PTR0: usize = 7;
const EPA_SECT1PTR1: usize = 8;
/// EPA entry count read (indexes 0..=9): the subvolume and raid fields
/// between them are carried but never patched.
const EPA_ENTRIES: usize = 10;

/// One sector-pointer map entry spans 10 bytes: a u64 LE LBA then a
/// u16 LE length.
const MAP_ENTRY_BYTES: usize = 10;

/// ADV pointers span 16 bytes: two u64 LE LBAs.
const ADVPTR_BYTES: usize = 16;

/// BIOS load address the extent merger walks: each file sector lands
/// `512` bytes past the previous one starting here.
const LOAD_ADDR: u64 = 0x8000;

/// One little-endian u16 out of `bytes` at `at`, refusing past the end
/// and naming the field and offset.
fn read_u16(bytes: &[u8], at: usize, field: &str) -> Result<u16> {
    let window = bytes.get(at..at + 2).ok_or_else(|| {
        CoreError::invalid(format!(
            "syslinux_patch: {field} at offset {at} runs past the {len} byte image: refusing",
            len = bytes.len()
        ))
    })?;
    let pair: [u8; 2] = window.try_into().map_err(|_| {
        CoreError::invalid(format!(
            "syslinux_patch: {field} at offset {at} is not two bytes: refusing"
        ))
    })?;
    Ok(u16::from_le_bytes(pair))
}

/// One little-endian u32 out of `bytes` at `at` (as [`read_u16`]).
fn read_u32(bytes: &[u8], at: usize, field: &str) -> Result<u32> {
    let window = bytes.get(at..at + 4).ok_or_else(|| {
        CoreError::invalid(format!(
            "syslinux_patch: {field} at offset {at} runs past the {len} byte image: refusing",
            len = bytes.len()
        ))
    })?;
    let word: [u8; 4] = window.try_into().map_err(|_| {
        CoreError::invalid(format!(
            "syslinux_patch: {field} at offset {at} is not four bytes: refusing"
        ))
    })?;
    Ok(u32::from_le_bytes(word))
}

/// The patched pair [`syslinux_patch`] returns: the core with its
/// sector map, pointers, directory and checksum written, and the VBR
/// with its two sector pointers written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patched {
    /// Patched core bytes (payload length, ADV not included).
    pub core: Vec<u8>,
    /// Patched VBR bytes (one sector).
    pub vbr: Vec<u8>,
}

/// Patch a Syslinux core and VBR for a file living at `sectors`.
///
/// `sectors` holds every 512-byte sector of the stage file in order:
/// `sectors[0]` is the file's first LBA and the list runs
/// `first_lba + i` for a contiguous install (the allocator guarantees
/// a sequential chain and `link_file` re-verifies it, which is why a
/// linear list is correct). Its length must equal
/// `ceil(core.len() / 512) + 2` — the core sectors plus the two ADV
/// sectors — and `subdir` (with its NUL byte) must fit the core's
/// `dirlen` field; the root install passes `b"/"`.
///
/// Steps, in upstream order: the VBR's two sector pointers name
/// `sectors[0]`; `data_sectors`/`adv_sectors`/`dwords` land in the
/// patch area; the sector-pointer map is zeroed and filled from
/// extents over `sectors[1 .. total - 2]`; the two ADV LBAs land at
/// the ADV pointer; the subdirectory string lands in the directory
/// field; the checksum over the first `dwords` dwords lands last.
///
/// Every malformed input is a [`CoreError::invalid`] naming the field
/// and offset in ASCII: a short core, no magic dword, an EPA or field
/// window past the end, a directory too small for the subdirectory, a
/// sector list whose length disagrees with the core, more extents than
/// `secptrcnt` allows, or an LBA/count that does not fit its field.
pub fn syslinux_patch(core: &[u8], vbr: &[u8], sectors: &[u64], subdir: &[u8]) -> Result<Patched> {
    let core_len = core.len();
    let scan_limit = core_len.checked_sub(PATCH_AREA_LEN).ok_or_else(|| {
        CoreError::invalid(format!(
            "syslinux_patch: core image is {core_len} bytes, shorter than the 0x18 byte patch area: refusing"
        ))
    })?;
    // The first dword equal to the magic, with the scan bound
    // `dword_index <= (len - 0x18) / 4` so the patch area fits past it.
    let mut magic_at: Option<usize> = None;
    for index in 0..=(scan_limit / 4) {
        let at = index * 4;
        let word = read_u32(core, at, "magic scan")?;
        if word == LDLINUX_MAGIC {
            magic_at = Some(at);
            break;
        }
    }
    let magic = magic_at.ok_or_else(|| {
        CoreError::invalid(format!(
            "syslinux_patch: core image of {core_len} bytes holds no LDLINUX magic dword 0x{LDLINUX_MAGIC:08x}: refusing"
        ))
    })?;

    let epa_offset = read_u16(core, magic + EPA_OFFSET_AT, "epaoffset")?;
    let epa = usize::from(epa_offset);
    let epa_end = epa.checked_add(EPA_ENTRIES * 2).ok_or_else(|| {
        CoreError::invalid(format!(
            "syslinux_patch: epa offset {epa} overflows the offset arithmetic: refusing"
        ))
    })?;
    if epa_end > core_len {
        return Err(CoreError::invalid(format!(
            "syslinux_patch: epa at offset {epa} with {EPA_ENTRIES} entries runs past the {core_len} byte core: refusing"
        )));
    }
    let mut epa_value = [0u16; EPA_ENTRIES];
    for (slot, value) in epa_value.iter_mut().enumerate() {
        *value = read_u16(core, epa + slot * 2, "epa entry")?;
    }
    let advptr = usize::from(epa_value[EPA_ADVPTR]);
    let diroffset = usize::from(epa_value[EPA_DIR]);
    let dirlen = usize::from(epa_value[EPA_DIRLEN]);
    let secptr = usize::from(epa_value[EPA_SECPTR]);
    let secptrcnt = usize::from(epa_value[EPA_SECPTRCNT]);
    let sect1ptr0 = usize::from(epa_value[EPA_SECT1PTR0]);
    let sect1ptr1 = usize::from(epa_value[EPA_SECT1PTR1]);

    // Every window the patch writes must sit inside its image.
    let map_bytes = secptrcnt.checked_mul(MAP_ENTRY_BYTES).ok_or_else(|| {
        CoreError::invalid(format!(
            "syslinux_patch: secptrcnt {secptrcnt} overflows the map arithmetic: refusing"
        ))
    })?;
    let map_end = secptr.checked_add(map_bytes).ok_or_else(|| {
        CoreError::invalid(format!(
            "syslinux_patch: sector map at offset {secptr} overflows the offset arithmetic: refusing"
        ))
    })?;
    if map_end > core_len {
        return Err(CoreError::invalid(format!(
            "syslinux_patch: sector map at offset {secptr} spans {map_bytes} bytes past the {core_len} byte core: refusing"
        )));
    }
    let advptr_end = advptr.checked_add(ADVPTR_BYTES).ok_or_else(|| {
        CoreError::invalid(format!(
            "syslinux_patch: adv pointers at offset {advptr} overflow the offset arithmetic: refusing"
        ))
    })?;
    if advptr_end > core_len {
        return Err(CoreError::invalid(format!(
            "syslinux_patch: adv pointers at offset {advptr} run past the {core_len} byte core: refusing"
        )));
    }
    let dir_end = diroffset.checked_add(dirlen).ok_or_else(|| {
        CoreError::invalid(format!(
            "syslinux_patch: directory at offset {diroffset} overflows the offset arithmetic: refusing"
        ))
    })?;
    if dir_end > core_len {
        return Err(CoreError::invalid(format!(
            "syslinux_patch: directory at offset {diroffset} with dirlen {dirlen} runs past the {core_len} byte core: refusing"
        )));
    }
    for (field, at) in [("sect1ptr0", sect1ptr0), ("sect1ptr1", sect1ptr1)] {
        let end = at.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "syslinux_patch: {field} at offset {at} overflows the offset arithmetic: refusing"
            ))
        })?;
        if end > vbr.len() {
            return Err(CoreError::invalid(format!(
                "syslinux_patch: {field} at offset {at} runs past the {} byte vbr: refusing",
                vbr.len()
            )));
        }
    }

    // The sector list must be exactly the core sectors plus the two
    // ADV sectors; anything else is a caller bug, refused here.
    let core_sectors = (core_len as u64).div_ceil(SECTOR_BYTES);
    let total = core_sectors.checked_add(ADV_SECTORS).ok_or_else(|| {
        CoreError::invalid(format!(
            "syslinux_patch: core of {core_len} bytes overflows the sector arithmetic: refusing"
        ))
    })?;
    if sectors.len() as u64 != total {
        return Err(CoreError::invalid(format!(
            "syslinux_patch: sector list holds {} entries but the {core_len} byte core needs {total}: refusing",
            sectors.len()
        )));
    }
    let data_sectors = u16::try_from(total - ADV_SECTORS).map_err(|_| {
        CoreError::invalid(format!(
            "syslinux_patch: data sector count {n} does not fit the 16-bit field: refusing",
            n = total - ADV_SECTORS
        ))
    })?;
    let dwords = u32::try_from(core_len / 4).map_err(|_| {
        CoreError::invalid(format!(
            "syslinux_patch: core of {core_len} bytes needs more dwords than the 32-bit field holds: refusing"
        ))
    })?;
    let first_sector = sectors
        .first()
        .ok_or_else(|| CoreError::invalid("syslinux_patch: sector list is empty: refusing"))?;
    let first_lba = u32::try_from(*first_sector).map_err(|_| {
        CoreError::invalid(format!(
            "syslinux_patch: first lba {first_sector} does not fit the 32-bit boot pointer: refusing"
        ))
    })?;

    let mut patched_core = core.to_vec();
    let mut patched_vbr = vbr.to_vec();

    // 1. Boot sector pointers name the file's first LBA.
    put_u32(&mut patched_vbr, sect1ptr0, first_lba)?;
    put_u32(&mut patched_vbr, sect1ptr1, 0)?;

    // 2. Patch-area counts: `dwords` is the floor, so a trailing
    // partial dword stays out of the checksum.
    put_u16(&mut patched_core, magic + DATA_SECTORS_AT, data_sectors)?;
    put_u16(
        &mut patched_core,
        magic + ADV_SECTORS_AT,
        ADV_SECTORS as u16,
    )?;
    put_u32(&mut patched_core, magic + DWORDS_AT, dwords)?;

    // 3. Zero the sector-pointer map, then fill it from extents over
    // `sectors[1 .. total - 2]` (sector 0 and both ADV sectors stay
    // out of the map).
    if let Some(window) = patched_core.get_mut(secptr..map_end) {
        window.fill(0);
    } else {
        return Err(CoreError::invalid(format!(
            "syslinux_patch: sector map at offset {secptr} vanished mid-copy: refusing"
        )));
    }
    let extents = merge_extents(
        sectors
            .get(1..sectors.len() - ADV_SECTORS as usize)
            .ok_or_else(|| {
                CoreError::invalid("syslinux_patch: sector list lost its data window: refusing")
            })?,
    )?;
    for (emitted, (lba, len)) in extents.iter().enumerate() {
        if emitted >= secptrcnt {
            return Err(CoreError::invalid(format!(
                "syslinux_patch: sector map needs more than the secptrcnt {secptrcnt} entries at offset {secptr}: refusing"
            )));
        }
        let at = secptr + emitted * MAP_ENTRY_BYTES;
        put_bytes(&mut patched_core, at, &lba.to_le_bytes())?;
        let len_field = u16::try_from(*len).map_err(|_| {
            CoreError::invalid(format!(
                "syslinux_patch: extent length {len} does not fit the 16-bit map field: refusing"
            ))
        })?;
        put_u16(&mut patched_core, at + 8, len_field)?;
    }

    // 5. ADV pointers: the last two sectors of the list.
    let adv_last = sectors
        .len()
        .checked_sub(1)
        .ok_or_else(|| CoreError::invalid("syslinux_patch: sector list is empty: refusing"))?;
    let adv_first_index = sectors.len().checked_sub(2).ok_or_else(|| {
        CoreError::invalid("syslinux_patch: sector list holds fewer than two entries: refusing")
    })?;
    let adv_first = sectors.get(adv_first_index).ok_or_else(|| {
        CoreError::invalid("syslinux_patch: sector list lost its adv window: refusing")
    })?;
    let adv_second = sectors.get(adv_last).ok_or_else(|| {
        CoreError::invalid("syslinux_patch: sector list lost its adv window: refusing")
    })?;
    put_bytes(&mut patched_core, advptr, &adv_first.to_le_bytes())?;
    put_bytes(&mut patched_core, advptr + 8, &adv_second.to_le_bytes())?;

    // 6. Subdirectory string with its NUL byte.
    let need = subdir.len().checked_add(1).ok_or_else(|| {
        CoreError::invalid("syslinux_patch: subdirectory length overflows: refusing")
    })?;
    if dirlen < need {
        return Err(CoreError::invalid(format!(
            "syslinux_patch: Subdirectory path too long... aborting install! dirlen {dirlen} holds fewer than the needed {need} bytes"
        )));
    }
    let dir_need_end = diroffset.checked_add(need).ok_or_else(|| {
        CoreError::invalid(format!(
            "syslinux_patch: directory at offset {diroffset} overflows the offset arithmetic: refusing"
        ))
    })?;
    let window = patched_core
        .get_mut(diroffset..dir_need_end)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "syslinux_patch: directory at offset {diroffset} vanished mid-copy: refusing"
            ))
        })?;
    let (name_area, terminator) = window.split_at_mut(subdir.len());
    name_area.copy_from_slice(subdir);
    if let Some(slot) = terminator.first_mut() {
        *slot = 0;
    } else {
        return Err(CoreError::invalid(format!(
            "syslinux_patch: directory at offset {diroffset} lost its terminator byte: refusing"
        )));
    }

    // 7. Checksum last: store zero, subtract every covered dword from
    // the magic, store the result.
    put_u32(&mut patched_core, magic + CHECKSUM_AT, 0)?;
    let mut checksum = LDLINUX_MAGIC;
    for index in 0..dwords {
        let at = (index as usize) * 4;
        checksum = checksum.wrapping_sub(read_u32(&patched_core, at, "checksum dword")?);
    }
    put_u32(&mut patched_core, magic + CHECKSUM_AT, checksum)?;

    Ok(Patched {
        core: patched_core,
        vbr: patched_vbr,
    })
}

/// Merge one sector run into `(lba, len)` extents, upstream's literal
/// algorithm: neighbours merge while the grown span stays under 64 KiB
/// and inside one 64 KiB page; with 512-byte sectors an extent caps at
/// 127 sectors (merging stops while `(len + 1) * 512 < 65536`).
fn merge_extents(sectors: &[u64]) -> Result<Vec<(u64, u64)>> {
    let mut extents: Vec<(u64, u64)> = Vec::new();
    let mut addr = LOAD_ADDR;
    let mut base = LOAD_ADDR;
    let mut len: u64 = 0;
    let mut lba: u64 = 0;
    for &sect in sectors {
        if len > 0 {
            let xbytes = (len + 1).checked_mul(SECTOR_BYTES).ok_or_else(|| {
                CoreError::invalid("syslinux_patch: extent span overflows: refusing")
            })?;
            let span_end = base
                .checked_add(xbytes)
                .and_then(|end| end.checked_sub(1))
                .ok_or_else(|| {
                    CoreError::invalid("syslinux_patch: extent end overflows: refusing")
                })?;
            let same_page = ((addr ^ span_end) & 0xffff_0000) == 0;
            let adjacent = sect
                == lba.checked_add(len).ok_or_else(|| {
                    CoreError::invalid("syslinux_patch: extent lba overflows: refusing")
                })?;
            if adjacent && xbytes < 65536 && same_page {
                len += 1;
            } else {
                extents.push((lba, len));
                base = addr;
                lba = sect;
                len = 1;
            }
        } else {
            base = addr;
            lba = sect;
            len = 1;
        }
        addr = addr.checked_add(SECTOR_BYTES).ok_or_else(|| {
            CoreError::invalid("syslinux_patch: load address overflows: refusing")
        })?;
    }
    if len > 0 {
        extents.push((lba, len));
    }
    // Growth is bounded by the input: at most one extent per sector,
    // and the caller enforces `secptrcnt` against the real count.
    Ok(extents)
}

/// Build the default 1024-byte ADV buffer (`syslinux_reset_adv`):
/// two identical 512-byte sectors, each opening with `0x5a2d2fa5`,
/// closing with `0xdd28bf64`, and carrying at offset 4 the seed minus
/// the wrapping sum of the u32s at 8, 12, ... 504 (exactly the seed
/// for the zeroed buffer).
#[must_use]
pub fn default_adv() -> [u8; ADV_BYTES] {
    let mut adv = [0u8; ADV_BYTES];
    for half in [0, SECTOR_BYTES as usize] {
        if let Some(window) = adv.get_mut(half..half + 4) {
            window.copy_from_slice(&ADV_MAGIC_START.to_le_bytes());
        }
        if let Some(window) = adv.get_mut(half + 508..half + 512) {
            window.copy_from_slice(&ADV_MAGIC_END.to_le_bytes());
        }
        // Checksum over the u32s at 8, 12, ... 504: the buffer is zero
        // there, so the sum is 0 and the stored value is exactly the
        // seed. Computed (not copied) so the relation stays explicit.
        let mut sum: u32 = 0;
        let mut at = half + 8;
        while at < half + 508 {
            if let Some(window) = adv.get(at..at + 4) {
                let mut word = [0u8; 4];
                word.copy_from_slice(window);
                sum = sum.wrapping_add(u32::from_le_bytes(word));
            }
            at += 4;
        }
        if let Some(window) = adv.get_mut(half + 4..half + 8) {
            window.copy_from_slice(&ADV_CHECKSUM_SEED.wrapping_sub(sum).to_le_bytes());
        }
    }
    adv
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `assets/resources/` next to the workspace root, without going
    /// through asset-dir resolution: every test below always executes.
    fn resources_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/resources"
        ))
    }

    /// Raw asset bytes (unverified: the patch tests pin the format, the
    /// manifest pins the bytes elsewhere).
    fn asset_bytes(name: &str) -> Vec<u8> {
        std::fs::read(resources_dir().join(name)).expect("the asset reads")
    }

    fn le16(bytes: &[u8], at: usize) -> u16 {
        let window = bytes.get(at..at + 2).expect("the test window fits");
        u16::from_le_bytes([window[0], window[1]])
    }

    fn le32(bytes: &[u8], at: usize) -> u32 {
        let window = bytes.get(at..at + 4).expect("the test window fits");
        u32::from_le_bytes([window[0], window[1], window[2], window[3]])
    }

    fn le64(bytes: &[u8], at: usize) -> u64 {
        let window = bytes.get(at..at + 8).expect("the test window fits");
        u64::from_le_bytes([
            window[0], window[1], window[2], window[3], window[4], window[5], window[6], window[7],
        ])
    }

    #[test]
    fn default_adv_carries_both_magics_and_the_seed() {
        let adv = default_adv();
        assert_eq!(adv.len(), ADV_BYTES, "the adv is two sectors");
        for half in [0, 512] {
            assert_eq!(
                le32(&adv, half),
                ADV_MAGIC_START,
                "each half opens with the lead magic"
            );
            assert_eq!(
                le32(&adv, half + 4),
                ADV_CHECKSUM_SEED,
                "the zeroed buffer checksums to exactly the seed"
            );
            assert_eq!(
                le32(&adv, half + 508),
                ADV_MAGIC_END,
                "each half closes with the tail magic"
            );
            assert!(
                adv[half + 8..half + 508].iter().all(|&byte| byte == 0),
                "the middle stays zero"
            );
        }
        assert_eq!(&adv[0..512], &adv[512..1024], "both halves are identical");
    }

    #[test]
    fn magic_scan_finds_offset_0x18_in_both_cores() {
        for name in ["RCDATA_401.bin", "RCDATA_403.bin"] {
            let core = asset_bytes(name);
            assert_eq!(
                le32(&core, MAGIC_OFFSET),
                LDLINUX_MAGIC,
                "{name} carries the magic at 0x18"
            );
        }
    }

    /// Patch `core`/`vbr` over a linear sector list starting at
    /// `first`, returning the patched pair.
    fn patch_linear(core: &[u8], vbr: &[u8], first: u64) -> Patched {
        let total = (core.len() as u64).div_ceil(SECTOR_BYTES) + ADV_SECTORS;
        let sectors: Vec<u64> = (0..total).map(|index| first + index).collect();
        syslinux_patch(core, vbr, &sectors, b"/").expect("the patch runs")
    }

    #[test]
    fn patch_407_pins_every_field() {
        let core = asset_bytes("RCDATA_401.bin");
        let vbr = asset_bytes("RCDATA_400.bin");
        let first = 4096u64;
        let patched = patch_linear(&core, &vbr, first);
        let out = &patched.core;
        // total = ceil(36488 / 512) + 2 = 74: 72 data, 2 adv, 9122
        // dwords over the floor.
        assert_eq!(
            le16(out, MAGIC_OFFSET + DATA_SECTORS_AT),
            72,
            "data sectors"
        );
        assert_eq!(le16(out, MAGIC_OFFSET + ADV_SECTORS_AT), 2, "adv sectors");
        assert_eq!(le32(out, MAGIC_OFFSET + DWORDS_AT), 9122, "dwords");
        // One extent: sectors[first + 1 .. first + 72) merge whole.
        assert_eq!(le64(out, 0x1ee), first + 1, "the extent lba");
        assert_eq!(le16(out, 0x1ee + 8), 71, "the extent length");
        assert!(
            out[0x1ee + 10..0x1ee + 1920].iter().all(|&byte| byte == 0),
            "the map past the written entry stays zero"
        );
        // ADV pointers name the last two sectors.
        assert_eq!(le64(out, 0x3798), first + 72, "first adv lba");
        assert_eq!(le64(out, 0x3798 + 8), first + 73, "second adv lba");
        // Directory holds "/" plus NUL.
        assert_eq!(&out[0x30bc..0x30bc + 2], b"/\x00", "the subdirectory");
        // Checksum recomputed independently: magic minus every covered
        // dword over a copy with the stored field zeroed, wrapping.
        let dwords = 9122usize;
        let mut probe = out.clone();
        probe[MAGIC_OFFSET + CHECKSUM_AT..MAGIC_OFFSET + CHECKSUM_AT + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        let mut again = LDLINUX_MAGIC;
        for index in 0..dwords {
            again = again.wrapping_sub(le32(&probe, index * 4));
        }
        assert_eq!(le32(out, MAGIC_OFFSET + CHECKSUM_AT), again, "the checksum");
        // VBR: first LBA at both pointers, everything else unchanged.
        assert_eq!(le32(&patched.vbr, 0x11a), first as u32, "low pointer");
        assert_eq!(le32(&patched.vbr, 0x120), 0, "high pointer");
        assert_eq!(&patched.vbr[0..0x11a], &vbr[0..0x11a], "vbr head");
        assert_eq!(&patched.vbr[0x11e..0x120], &vbr[0x11e..0x120], "vbr gap");
        assert_eq!(&patched.vbr[0x124..], &vbr[0x124..], "vbr tail");
    }

    #[test]
    fn patch_604_splits_at_127_sectors() {
        let core = asset_bytes("RCDATA_403.bin");
        let vbr = asset_bytes("RCDATA_402.bin");
        let first = 8192u64;
        let patched = patch_linear(&core, &vbr, first);
        let out = &patched.core;
        // total = ceil(68121 / 512) + 2 = 136: 134 data, 2 adv, 17030
        // dwords.
        assert_eq!(
            le16(out, MAGIC_OFFSET + DATA_SECTORS_AT),
            134,
            "data sectors"
        );
        assert_eq!(le16(out, MAGIC_OFFSET + ADV_SECTORS_AT), 2, "adv sectors");
        assert_eq!(le32(out, MAGIC_OFFSET + DWORDS_AT), 17030, "dwords");
        // 133 mapped sectors split at the 127 cap: (first+1, 127) then
        // (first+128, 6).
        assert_eq!(le64(out, 0x1ee), first + 1, "first extent lba");
        assert_eq!(le16(out, 0x1ee + 8), 127, "first extent length");
        assert_eq!(le64(out, 0x1ee + 10), first + 128, "second extent lba");
        assert_eq!(le16(out, 0x1ee + 18), 6, "second extent length");
        assert!(
            out[0x1ee + 20..0x1ee + 1920].iter().all(|&byte| byte == 0),
            "the map past the written entries stays zero"
        );
        assert_eq!(le64(out, 0x16d8), first + 134, "first adv lba");
        assert_eq!(le64(out, 0x16d8 + 8), first + 135, "second adv lba");
        assert_eq!(&out[0x145c..0x145c + 2], b"/\x00", "the subdirectory");
        assert_eq!(le32(&patched.vbr, 0x11a), first as u32, "low pointer");
        assert_eq!(le32(&patched.vbr, 0x120), 0, "high pointer");
    }

    #[test]
    fn merge_splits_fragmented_runs() {
        // Four runs over a 4.07-sized list: lengths 10, 1, 6 and the
        // contiguous rest.
        let core = asset_bytes("RCDATA_401.bin");
        let total = (core.len() as u64).div_ceil(SECTOR_BYTES) + ADV_SECTORS;
        let mut sectors: Vec<u64> = Vec::new();
        sectors.push(5000);
        for index in 0..10 {
            sectors.push(6000 + index);
        }
        sectors.push(7000);
        for index in 0..6 {
            sectors.push(8000 + index);
        }
        let mut next = 9000u64;
        while sectors.len() < total as usize {
            sectors.push(next);
            next += 1;
        }
        assert_eq!(sectors.len() as u64, total, "the list keeps its length");
        let vbr = asset_bytes("RCDATA_400.bin");
        let patched = syslinux_patch(&core, &vbr, &sectors, b"/").expect("the patch runs");
        let out = &patched.core;
        assert_eq!(le64(out, 0x1ee), 6000, "first run lba");
        assert_eq!(le16(out, 0x1ee + 8), 10, "first run length");
        assert_eq!(le64(out, 0x1ee + 10), 7000, "lone sector lba");
        assert_eq!(le16(out, 0x1ee + 18), 1, "lone sector length");
        assert_eq!(le64(out, 0x1ee + 20), 8000, "third run lba");
        assert_eq!(le16(out, 0x1ee + 28), 6, "third run length");
        let rest = total - 2 - 1 - 10 - 1 - 6;
        assert_eq!(le64(out, 0x1ee + 30), 9000, "last run lba");
        assert_eq!(le16(out, 0x1ee + 38), rest as u16, "last run length");
    }

    #[test]
    fn patch_refuses_malformed_inputs() {
        let core = asset_bytes("RCDATA_401.bin");
        let vbr = asset_bytes("RCDATA_400.bin");
        let total = (core.len() as u64).div_ceil(SECTOR_BYTES) + ADV_SECTORS;
        let linear: Vec<u64> = (0..total).map(|index| 4096 + index).collect();
        let text_of = |result: Result<Patched>| result.expect_err("malformed refuses").to_string();

        // A short core refuses.
        let text = text_of(syslinux_patch(&core[..100], &vbr, &linear, b"/"));
        assert!(text.contains("100"), "names the length: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");

        // No magic refuses.
        let mut blurred = core.clone();
        blurred[MAGIC_OFFSET..MAGIC_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        let text = text_of(syslinux_patch(&blurred, &vbr, &linear, b"/"));
        assert!(text.contains("magic"), "names the magic: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");

        // An EPA offset past the end refuses.
        let mut wild = core.clone();
        let epa_at = MAGIC_OFFSET + EPA_OFFSET_AT;
        wild[epa_at..epa_at + 2].copy_from_slice(&0xFFF0u16.to_le_bytes());
        let text = text_of(syslinux_patch(&wild, &vbr, &linear, b"/"));
        assert!(text.contains("epa"), "names the epa: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");

        // A dirlen too small for "/" refuses with the reference words.
        let mut narrow = core.clone();
        // EPA[2] sits at epaoffset + 4; the 4.07 epaoffset is 0x30a6.
        narrow[0x30aa..0x30aa + 2].copy_from_slice(&1u16.to_le_bytes());
        let text = text_of(syslinux_patch(&narrow, &vbr, &linear, b"/"));
        assert!(
            text.contains("Subdirectory path too long"),
            "the reference wording: {text}"
        );
        assert!(text.contains('1'), "names the dirlen: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");

        // A sector list of the wrong length refuses.
        let text = text_of(syslinux_patch(&core, &vbr, &linear[..10], b"/"));
        assert!(text.contains("10"), "names the list length: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");

        // More extents than secptrcnt allows refuses: narrow the
        // asset's own count to 2, then force 3 extents with gaps.
        let mut narrow_map = core.clone();
        narrow_map[0x30b2..0x30b2 + 2].copy_from_slice(&2u16.to_le_bytes());
        let mut gapped: Vec<u64> = vec![4096, 8192, 8194, 8196];
        while gapped.len() < total as usize {
            let next = gapped[gapped.len() - 1] + 1;
            gapped.push(next);
        }
        let text = text_of(syslinux_patch(&narrow_map, &vbr, &gapped, b"/"));
        assert!(text.contains('2'), "names secptrcnt: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");

        // A short VBR refuses naming the pointer field.
        let text = text_of(syslinux_patch(&core, &vbr[..0x11a], &linear, b"/"));
        assert!(text.contains("sect1ptr0"), "names the field: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }
}
