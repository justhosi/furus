//! The anchor volume descriptor pointer (S15, slice 1).
//!
//! The anchor (tag id 2) is the UDF entry point: it sits at logical
//! sector 256 and carries the main and reserve volume descriptor sequence
//! extents as (length, location) pairs. The logical sector size is not
//! known up front, so [`probe`] tries the two block sizes the writer
//! side supports (see [`BlockSize`](crate::fs::udf::BlockSize)): 2048
//! first (the mandated image shape), then 512. A candidate wins only when
//! the block at sector 256 parses as tag id 2, claims location 256 and
//! passes its CRC.
//!
//! *Measured* — on the `mkudffs --udfrev=0x0201` images from udftools 2.3
//! (see the slice report): the anchor sits at byte `256 * block size`
//! for both `-b 2048` and `-b 512`, the main extent is 16 blocks at
//! location 96, and the reserve extent is a second 16-block extent 160
//! blocks before the volume end (block 32608 of 32768 on the 64MiB
//! `-b 2048` image, block 130912 of 131072 on the 64MiB `-b 512`
//! image) carrying the same descriptors with their tags written for
//! their own block numbers. Both extents are block multiples and sit
//! fully inside the store.
//!
//! *Inferred* — nothing here: the extent validation (non-zero length,
//! block multiple, inside the store) is defensive arithmetic, and the
//! reserve-as-fallback strategy in [`reader`](super::reader) follows from
//! the measured second-extent layout.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::udf::PROBE_BLOCK_SIZES;
use crate::udf::le_u32;
use crate::udf::read_block;
use crate::udf::tag;

/// Logical sector number of the anchor volume descriptor pointer.
pub const ANCHOR_SECTOR: u32 = 256;

/// Anchor tag id.
const TAG_ANCHOR: u16 = 2;

/// Offset of the main volume descriptor sequence extent (length then
/// location, `u32` each) inside the anchor block.
const MAIN_AT: usize = 16;

/// Offset of the reserve extent, same shape as the main one.
const RESERVE_AT: usize = 24;

/// One volume descriptor sequence extent: byte length and starting block
/// number, both in units of the probed block size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    /// Extent length in bytes (a multiple of the block size, never zero).
    pub length: u32,
    /// Starting block number of the extent.
    pub location: u32,
}

/// The probed anchor: the winning block size with both extents. A zero
/// reserve length means the volume carries no reserve sequence (`None`);
/// anything else is validated like the main extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    /// Block size in bytes that validated at sector 256.
    pub block_size: u32,
    /// Main volume descriptor sequence extent.
    pub main: Extent,
    /// Reserve extent (`None` when its length is zero).
    pub reserve: Option<Extent>,
}

/// Find the anchor at sector 256: try each [`PROBE_BLOCK_SIZES`] entry in
/// order and keep the first whose block parses as tag id 2, claims
/// location 256 and passes its CRC. Refuses when no candidate validates,
/// naming sector 256, both tried sizes and each size's failure reason.
pub fn probe(volume: &dyn Volume) -> Result<Anchor> {
    let total = volume.total_bytes();
    let mut failures: Vec<String> = Vec::new();
    for size in PROBE_BLOCK_SIZES {
        match read_block(volume, ANCHOR_SECTOR, size, total, "anchor candidate") {
            Err(error) => {
                failures.push(format!("{size} byte blocks: {error}"));
            }
            Ok(block) => match check_anchor(&block, size, total) {
                Ok(anchor) => return Ok(anchor),
                Err(error) => {
                    failures.push(format!("{size} byte blocks: {error}"));
                }
            },
        }
    }
    if failures.is_empty() {
        failures.push(String::from("no candidate block was readable"));
    }
    Err(CoreError::invalid(format!(
        "no UDF anchor volume descriptor pointer found at sector {ANCHOR_SECTOR} \
         (tried {} byte blocks): {}",
        PROBE_BLOCK_SIZES
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(" and "),
        failures.join("; "),
    )))
}

/// Validate one candidate anchor block read with `size` byte blocks:
/// tag id 2, location 256, a passing CRC, and two sane extents.
fn check_anchor(block: &[u8], size: u32, total: u64) -> Result<Anchor> {
    let tag = tag::parse(block, "anchor volume descriptor pointer")?;
    if tag.id != TAG_ANCHOR {
        return Err(CoreError::invalid(format!(
            "block {ANCHOR_SECTOR} of {size} byte blocks has tag id {} not {TAG_ANCHOR}: \
             not an anchor volume descriptor pointer",
            tag.id
        )));
    }
    if tag.location != ANCHOR_SECTOR {
        return Err(CoreError::invalid(format!(
            "anchor volume descriptor pointer claims tag location {} not {ANCHOR_SECTOR}: \
             refusing a pointer that does not describe its own block",
            tag.location
        )));
    }
    tag::verify_crc(block, &tag, "anchor volume descriptor pointer")?;
    let main = extent_at(block, MAIN_AT, size, total, "main")?;
    let reserve_len = le_u32(block, RESERVE_AT, "anchor volume descriptor pointer")?;
    let reserve = if reserve_len == 0 {
        None
    } else {
        Some(extent_at(block, RESERVE_AT, size, total, "reserve")?)
    };
    Ok(Anchor {
        block_size: size,
        main,
        reserve,
    })
}

/// Parse and validate the (length, location) extent at `at`: non-zero
/// length, a multiple of the block size, and fully inside the store. The
/// zero-length refusal carries the words `zero length` so [`check_anchor`]
/// can tell "no reserve sequence" apart from a corrupt one.
fn extent_at(block: &[u8], at: usize, size: u32, total: u64, which: &str) -> Result<Extent> {
    let what = "anchor volume descriptor pointer";
    let length = le_u32(block, at, what)?;
    let location = le_u32(block, at + 4, what)?;
    if length == 0 {
        return Err(CoreError::invalid(format!(
            "anchor volume descriptor pointer {which} volume descriptor sequence extent \
             has zero length: no {which} sequence to walk"
        )));
    }
    if !length.is_multiple_of(size) {
        return Err(CoreError::invalid(format!(
            "anchor volume descriptor pointer {which} sequence extent length {length} is not \
             a multiple of the {size} byte block size"
        )));
    }
    let start = u64::from(location)
        .checked_mul(u64::from(size))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "anchor volume descriptor pointer {which} sequence extent at block {location} \
                 overflows the byte offset arithmetic"
            ))
        })?;
    let end = start.checked_add(u64::from(length)).ok_or_else(|| {
        CoreError::invalid(format!(
            "anchor volume descriptor pointer {which} sequence extent of {length} bytes at \
             block {location} overflows the byte offset arithmetic"
        ))
    })?;
    if end > total {
        return Err(CoreError::invalid(format!(
            "anchor volume descriptor pointer {which} sequence extent of {length} bytes at \
             block {location} (bytes {start}..{end}) runs past the {total} byte volume end"
        )));
    }
    Ok(Extent { length, location })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::udf::stamp_tag;

    /// Anchor block for `size` byte blocks: tag id 2 at location 256, a
    /// 16-block main extent at 96 and a 16-block reserve at `reserve`,
    /// with the CRC fixed. Synthetic layout only.
    fn anchor_block(size: u32, reserve: u32) -> Vec<u8> {
        let mut block = vec![0u8; size as usize];
        let main_len = 16 * size;
        block[16..20].copy_from_slice(&main_len.to_le_bytes());
        block[20..24].copy_from_slice(&96u32.to_le_bytes());
        block[24..28].copy_from_slice(&main_len.to_le_bytes());
        block[28..32].copy_from_slice(&reserve.to_le_bytes());
        stamp_tag(&mut block, TAG_ANCHOR, (size - 16) as u16, ANCHOR_SECTOR);
        block
    }

    /// Store of `sectors` 2048-byte blocks with `block` written at 2048-
    /// byte block `at`, boxed for the probe.
    fn store_2048(block: &[u8], at: u32, sectors: u32) -> VecVolume {
        let mut volume =
            VecVolume::new(u64::from(sectors) * 2048, 512).expect("the fixture fits in RAM");
        volume
            .write_all_at(u64::from(at) * 2048, block)
            .expect("the anchor fits");
        volume
    }

    #[test]
    fn probe_finds_the_2048_anchor() {
        let anchor = anchor_block(2048, 8032);
        let volume = store_2048(&anchor, ANCHOR_SECTOR, 9000);
        let found = probe(&volume).expect("the anchor validates");
        assert_eq!(found.block_size, 2048);
        assert_eq!(
            found.main,
            Extent {
                length: 16 * 2048,
                location: 96
            }
        );
        assert_eq!(
            found.reserve,
            Some(Extent {
                length: 16 * 2048,
                location: 8032
            })
        );
    }

    #[test]
    fn probe_falls_through_to_512() {
        // A 512-byte-block volume: the 2048-byte read at sector 256 lands
        // on zeroes (wrong tag id), the 512-byte read validates.
        let anchor = anchor_block(512, 32608);
        let mut volume = VecVolume::new(16 * 1024 * 1024, 512).expect("the fixture fits in RAM");
        volume
            .write_all_at(u64::from(ANCHOR_SECTOR) * 512, &anchor)
            .expect("the anchor fits");
        let found = probe(&volume).expect("the 512 anchor validates");
        assert_eq!(found.block_size, 512);
        assert_eq!(found.main.location, 96);
    }

    #[test]
    fn zero_reserve_length_means_no_reserve() {
        let mut anchor = anchor_block(2048, 8032);
        anchor[24..32].copy_from_slice(&[0u8; 8]);
        // Re-fix the CRC after zeroing the reserve extent.
        stamp_tag(&mut anchor, TAG_ANCHOR, 2048 - 16, ANCHOR_SECTOR);
        let volume = store_2048(&anchor, ANCHOR_SECTOR, 9000);
        let found = probe(&volume).expect("the anchor validates");
        assert_eq!(found.reserve, None);
    }

    #[test]
    fn missing_anchor_names_sector_256_and_both_sizes() {
        let volume = VecVolume::new(16 * 1024 * 1024, 512).expect("zeroes fit in RAM");
        let error = probe(&volume).expect_err("zeroes carry no anchor");
        let text = error.to_string();
        assert!(text.contains("256"), "{text}");
        assert!(text.contains("2048"), "{text}");
        assert!(text.contains("512"), "{text}");
    }

    #[test]
    fn wrong_tag_id_refuses() {
        let mut anchor = anchor_block(2048, 8032);
        anchor[0..2].copy_from_slice(&1u16.to_le_bytes());
        stamp_tag(&mut anchor, 1, 2048 - 16, ANCHOR_SECTOR);
        let volume = store_2048(&anchor, ANCHOR_SECTOR, 9000);
        let error = probe(&volume).expect_err("tag id 1 is no anchor");
        let text = error.to_string();
        assert!(text.contains("256"), "{text}");
    }

    #[test]
    fn location_mismatch_refuses() {
        let mut anchor = anchor_block(2048, 8032);
        stamp_tag(&mut anchor, TAG_ANCHOR, 2048 - 16, 257);
        let volume = store_2048(&anchor, ANCHOR_SECTOR, 9000);
        let error = probe(&volume).expect_err("location 257 refuses");
        let text = error.to_string();
        assert!(text.contains("257"), "{text}");
        assert!(text.contains("256"), "{text}");
    }

    #[test]
    fn crc_mismatch_refuses() {
        let mut anchor = anchor_block(2048, 8032);
        anchor[40] ^= 0xFF;
        let volume = store_2048(&anchor, ANCHOR_SECTOR, 9000);
        let error = probe(&volume).expect_err("the flipped byte refuses");
        let text = error.to_string();
        assert!(text.contains("mismatch"), "{text}");
    }

    #[test]
    fn zero_length_main_extent_refuses() {
        let mut anchor = anchor_block(2048, 8032);
        anchor[16..20].copy_from_slice(&0u32.to_le_bytes());
        stamp_tag(&mut anchor, TAG_ANCHOR, 2048 - 16, ANCHOR_SECTOR);
        let volume = store_2048(&anchor, ANCHOR_SECTOR, 9000);
        let error = probe(&volume).expect_err("a zero-length main extent refuses");
        let text = error.to_string();
        assert!(text.contains("zero length"), "{text}");
        assert!(text.contains("main"), "{text}");
    }

    #[test]
    fn extent_past_the_store_refuses() {
        let mut anchor = anchor_block(2048, 8032);
        anchor[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        stamp_tag(&mut anchor, TAG_ANCHOR, 2048 - 16, ANCHOR_SECTOR);
        let volume = store_2048(&anchor, ANCHOR_SECTOR, 9000);
        let error = probe(&volume).expect_err("an extent past the end refuses");
        let text = error.to_string();
        assert!(text.contains("runs past"), "{text}");
    }
}
