//! The FAT32 volume writer (S09 part A): superblocks, both FATs and
//! the root directory, laid out in the order the FAT32 spec explains,
//! through the [`crate::fs::Volume`] byte store.
//!
//! What it builds, byte by byte, in one [`format`] pass:
//!
//! 1. the boot sector at byte 0 and its backup at reserved sector 6,
//!    the FSInfo structure at reserved sector 1 and its backup at
//!    sector 7 — the FAT32 spec positions, each at a
//!    `sector_size`-multiple offset of the volume stack;
//! 2. both FAT copies (reserved sectors 32.. and on), with entries 0,
//!    1 and 2 pinned (`0x0FFFFFF8` media, `0x0FFFFFFF` EoC,
//!    `0x0FFFFFFF` for the root cluster — the root directory is one
//!    cluster whose only member is, optionally, the volume label
//!    entry) and everything else zeroed. The copies are written
//!    through a bounded, reused 64 KiB stack chunk — never a whole-FAT
//!    `Vec`, which would be 134 MB for a 2 TiB volume — and the two
//!    copies are byte-identical by construction, asserted in tests;
//! 3. the root directory cluster zero-filled, followed by the
//!    single volume-label entry (attribute `0x08`, the 11 label bytes
//!    of [`bpb`]'s one label encoder, all timestamps zero — part B's
//!    `set_times` fills them) when a caller supplied a label.
//!
//! The reserved sectors that carry neither a boot copy nor the FSInfo,
//! and everything past the FATs that is not the root cluster, are left
//! untouched: a fresh sparse store is already zero there, and a wiping
//! pass belongs to the caller's pipeline, not to the formatter.
//!
//! [`format`] also refuses anything that would write a volume the
//! caller sized differently (a shifty `Volume::total_bytes`) and
//! anything whose volume id is the blank `0`.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::fs::fat32::bpb;
use crate::fs::fat32::bpb::label_field;
use crate::fs::fat32::geometry::BACKUP_BOOT_SECTOR;
use crate::fs::fat32::geometry::FSINFO_SECTOR;
use crate::fs::fat32::geometry::Geometry;
use crate::fs::fat32::geometry::NUM_FATS;
use crate::fs::fat32::geometry::ROOT_CLUSTER;
use crate::fs::fat32::geometry::geometry;
use crate::fs::fat32::put_bytes;
use crate::fs::fat32::put_u32;

/// One FAT32 entry of the FAT scaffolding: the media descriptor
/// (`0x0FFFFFF8` = `0xF8` plus the FAT family high bits) in entry 0,
/// the end-of-chain marker in entry 1, and the root cluster's own
/// end-of-chain in entry 2 — the root directory is exactly one
/// cluster at format time.
const ROOT_EOC_ENTRY: u32 = 0x0FFF_FFFF;
const MEDIA_ENTRY: u32 = 0x0FFF_FFF8;

/// The volume-label directory entry attribute: the read-only system
/// bits no directory listing edits.
const VOLUME_LABEL_ATTRIBUTE: u8 = 0x08;

/// The bounded stack chunk every long interior write goes through.
/// 64 KiB covers a whole worst-case cluster (and root directory), so
/// the FAT copies and the root cluster each cost one buffer at most.
const FILL_CHUNK_BYTES: usize = 64 * 1024;

/// The write-side options of [`format`], everything beyond the volume
/// bytes themselves.
///
/// The label validates through [`bpb`]'s one label encoder: uppercase
/// ASCII at most 11 bytes west for the BPB and one root entry;
/// cropping belongs to the file API's `set_label`, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatOptions<'a> {
    /// Volume label to bake into the BPB and as a root-directory
    /// entry; `None` builds the `NO NAME    ` BPB field and no entry.
    pub label: Option<&'a str>,
    /// 32-bit volume id ("serial"). `0` is refused — the caller must
    /// generate a real one (a fresh pseudo-random value per format,
    /// as Rufus does), because `0` marks unformatted media and two
    /// freshly formatted sticks must stay distinguishable.
    pub volume_id: u32,
    /// The partition's first sector in units of the volume's sector
    /// size, written to the BPB's hidden-sectors field: the mkfs step
    /// passes the data partition's start LBA, a plain volume (a
    /// superfloppy, a test image) passes `0`.
    pub hidden_sectors: u32,
    /// OEM name bytes, written verbatim; [`bpb::DEFAULT_OEM`] carries
    /// Rufus's `MSWIN4.1`.
    pub oem: [u8; 8],
}

impl Default for FormatOptions<'_> {
    /// Builds the struct-level shape, *not* a valid request: the
    /// volume id stays `0` (refused by [`format`]) because the caller
    /// must supply a real one; the hidden sectors are `0` (a whole
    /// volume, no partition in front), the OEM name is Rufus's and the
    /// label empty. Intended for `spread { ..Default::default() }`-style
    /// extension, not for direct submission.
    fn default() -> Self {
        Self {
            label: None,
            volume_id: 0,
            hidden_sectors: 0,
            oem: bpb::DEFAULT_OEM,
        }
    }
}

/// Format a whole FAT32 volume onto `volume` and return the geometry.
///
/// The volume's own `total_bytes` and `sector_size` decide the layout;
/// both are re-read right before the first byte moves, so a caller
/// cannot accidentally format a volume it sized differently — a drift
/// in either measurement is refused naming the two readings.
///
/// Failures (all [`CoreError::invalid`] unless the store itself
/// reports I/O): the size class is refused by [`geometry`], a mis-sized
/// volume is refused by the cross-check, a `0` volume id is refused,
/// and any store error bubbles up as it happened.
pub fn format(volume: &mut dyn Volume, options: &FormatOptions<'_>) -> Result<Geometry> {
    if options.volume_id == 0 {
        return Err(CoreError::invalid(
            "volume id 0 is refused: the caller must generate a real one",
        ));
    }
    let geometry = geometry(volume.total_bytes(), volume.sector_size())?;
    // The sizing cross-check: both geometry inputs are re-read so a
    // volume that grew, shrank or resynced its sector size after the
    // derivation is refused instead of formatted into a different
    // shape than the caller asked for.
    if volume.total_bytes() != geometry.total_bytes
        || volume.sector_size() != u32::from(geometry.bytes_per_sector)
    {
        let now = volume.total_bytes();
        let derived = geometry.total_bytes;
        return Err(CoreError::invalid(format!(
            "volume reported {now} bytes this round but the geometry was derived for {derived} bytes"
        )));
    }

    let input = bpb::BootSectorInput {
        geometry: &geometry,
        volume_id: options.volume_id,
        hidden_sectors: options.hidden_sectors,
        label: options.label,
        oem: options.oem,
    };
    let boot = bpb::boot_sector(&input)?;
    let fsinfo_image = bpb::fsinfo();
    let backup_boot = bpb::backup_boot_sector(&boot);

    volume.write_all_at(0, &boot)?;
    volume.write_all_at(reserved_offset(&geometry, FSINFO_SECTOR)?, &fsinfo_image)?;
    volume.write_all_at(
        reserved_offset(&geometry, BACKUP_BOOT_SECTOR)?,
        &backup_boot,
    )?;
    volume.write_all_at(
        reserved_offset(
            &geometry,
            BACKUP_BOOT_SECTOR
                .checked_add(FSINFO_SECTOR)
                .ok_or_else(|| {
                    CoreError::invalid("the backup fsinfo sector number overflows a u32")
                })?,
        )?,
        &fsinfo_image,
    )?;

    for index in 0..u32::from(NUM_FATS) {
        write_fat(volume, &geometry, index)?;
    }

    // The root directory: zero the cluster, then (with a label) its
    // single volume-label entry as the chunk prefix.
    let label_entry = match options.label {
        Some(_) => {
            let field = label_field(options.label)?;
            volume_label_entry(&field)
        }
        None => [0u8; 32],
    };
    let root = geometry.cluster_offset(ROOT_CLUSTER).ok_or_else(|| {
        CoreError::invalid("the root cluster has no byte window in the resolved geometry")
    })?;
    chunked_write(volume, root, geometry.cluster_bytes(), &label_entry)?;

    volume.flush()?;
    Ok(geometry)
}

/// Absolute byte offset of reserved-sector number `index` (the boot
/// region constants of [`geometry`] live here).
fn reserved_offset(geometry: &Geometry, index: u32) -> Result<u64> {
    u64::from(geometry.bytes_per_sector)
        .checked_mul(u64::from(index))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "reserved sector {index}'s byte offset overflows a u64"
            ))
        })
}

/// Write FAT copy `index`: the three scaffolding entries, then zeros
/// to the FAT's full length, through the bounded chunk.
fn write_fat(volume: &mut dyn Volume, geometry: &Geometry, index: u32) -> Result<()> {
    let mut scaffolding = [0u8; 12];
    put_u32(&mut scaffolding, 0, MEDIA_ENTRY).ok();
    put_u32(&mut scaffolding, 4, ROOT_EOC_ENTRY).ok();
    put_u32(&mut scaffolding, 8, ROOT_EOC_ENTRY).ok();
    let start = geometry
        .fat_offset()
        .checked_add(
            u64::from(index)
                .checked_mul(geometry.fat_length_bytes())
                .ok_or_else(|| CoreError::invalid("a fat copy's byte offset overflows a u64"))?,
        )
        .ok_or_else(|| CoreError::invalid("a fat copy sits beyond the volume"))?;
    chunked_write(volume, start, geometry.fat_length_bytes(), &scaffolding)
}

/// The 32-byte root directory entry for a volume label: the 11 label
/// bytes, the [`VOLUME_LABEL_ATTRIBUTE`] attribute, and everything
/// else zero (NT reserved fields, the timestamps — part B's
/// `set_times` maintains them — first cluster hint and size).
///
/// Infallible by construction: fixed constants inside the 32-byte
/// entry, so the [`put_bytes`] results (totality plumbing) cannot miss
/// and are dropped with `ok`, exactly like [`bpb::fsinfo`].
fn volume_label_entry(label: &[u8; 11]) -> [u8; 32] {
    let mut entry = [0u8; 32];
    put_bytes(&mut entry, 0, label).ok();
    put_bytes(&mut entry, 11, &[VOLUME_LABEL_ATTRIBUTE]).ok();
    entry
}

/// Write `length` bytes from `start`: the `prefix` first, zeros after,
/// through one reused bounded chunk — no whole-region allocation even
/// for the 134 MB FAT copies of a 2 TiB volume. The prefix shorter
/// than the chunk is a format-time invariant; a surprise surfaces as
/// [`CoreError::invalid`], never a panic.
fn chunked_write(volume: &mut dyn Volume, start: u64, length: u64, prefix: &[u8]) -> Result<()> {
    let mut chunk = [0u8; FILL_CHUNK_BYTES];
    if prefix.len() > FILL_CHUNK_BYTES {
        return Err(CoreError::invalid(
            "region prefix does not fit the write chunk",
        ));
    }
    if let Some(window) = chunk.get_mut(..prefix.len()) {
        window.copy_from_slice(prefix);
    } else {
        return Err(CoreError::invalid("region prefix window vanished mid-copy"));
    }
    let mut done = 0_u64;
    while done < length {
        let piece = usize::try_from((length - done).min(FILL_CHUNK_BYTES as u64))
            .map_err(|_| CoreError::invalid("a chunk piece does not fit usize"))?;
        let offset = start
            .checked_add(done)
            .ok_or_else(|| CoreError::invalid("a chunk piece's byte offset overflows a u64"))?;
        volume.write_all_at(offset, &chunk[..piece])?;
        done += piece as u64; // `piece` is usize, always widening here
        // from the second piece on, only zeros travel: the prefix must
        // not reappear at every chunk boundary (the pinned FAT-image
        // test caught exactly that divergence once).
        if let Some(window) = chunk.get_mut(..prefix.len()) {
            window.fill(0);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::fs::fat32::bpb::BOOT_SECTOR_BYTES;
    use std::cell::Cell;
    use std::io;
    use std::sync::OnceLock;

    /// 64 MiB in bytes, the canonical small target here.
    const SIXTY_FOUR_MIB: u64 = 64 * 1024 * 1024;

    /// The sample geometry (the 64 MiB row of the pinned table: FAT
    /// 1009, 129,022 clusters) plus the matching options the images
    /// of these tests use. `OnceLock` keeps the mutation local and
    /// freezes the geometry for the &'static the boot inputs take.
    fn sample() -> &'static (Geometry, FormatOptions<'static>) {
        static SAMPLE: OnceLock<(Geometry, FormatOptions<'static>)> = OnceLock::new();
        SAMPLE.get_or_init(|| {
            let set = geometry(SIXTY_FOUR_MIB, 512).expect("64 MiB geometry");
            let options = FormatOptions {
                label: Some("Rufus"),
                volume_id: 0x1A2B_3C4D,
                hidden_sectors: 2048,
                oem: bpb::DEFAULT_OEM,
            };
            (set, options)
        })
    }

    #[test]
    fn format_writes_the_complete_layout_in_order() {
        let (geometry, options) = sample();
        let mut volume = VecVolume::new(SIXTY_FOUR_MIB, 512).expect("64 MiB of RAM");
        let report = format(&mut volume, options).expect("the 64 MiB volume formats");
        assert_eq!(report, *geometry, "the report is the derived geometry");

        // the four superblock images, each at its own sector slot
        let sector = u64::from(geometry.bytes_per_sector);
        let boot_image = bpb::boot_sector(&bpb::BootSectorInput {
            geometry,
            volume_id: options.volume_id,
            hidden_sectors: options.hidden_sectors,
            label: options.label,
            oem: options.oem,
        })
        .expect("the boot image builds");
        let fsinfo_image = bpb::fsinfo();
        let mut window = [0u8; BOOT_SECTOR_BYTES];
        volume.read_exact_at(0, &mut window).expect("boot at 0");
        assert_eq!(window, boot_image, "primary boot sector");
        volume
            .read_exact_at(6 * sector, &mut window)
            .expect("backup boot at 6");
        assert_eq!(window, boot_image, "backup boot sector at reserved 6");
        volume
            .read_exact_at(sector, &mut window)
            .expect("fsinfo at 1");
        assert_eq!(window, fsinfo_image, "fsinfo at reserved 1");
        volume
            .read_exact_at(7 * sector, &mut window)
            .expect("backup fsinfo at 7");
        assert_eq!(window, fsinfo_image, "backup fsinfo at reserved 7");

        // both FAT copies byte-identical, scaffolding pinned, slack
        // (and everything past the clusters' entries) zero
        let fat_bytes = geometry.fat_length_bytes() as usize;
        let mut fat_one = vec![0u8; fat_bytes];
        let mut fat_two = vec![0u8; fat_bytes];
        volume
            .read_exact_at(geometry.fat_offset(), &mut fat_one)
            .expect("fat 1 read");
        volume
            .read_exact_at(
                geometry.fat_offset() + geometry.fat_length_bytes(),
                &mut fat_two,
            )
            .expect("fat 2 read");
        assert_eq!(fat_one, fat_two, "both FAT copies are identical");
        let expected = [
            0x0FFF_FFF8u32.to_le_bytes(),
            0x0FFF_FFFFu32.to_le_bytes(),
            0x0FFF_FFFFu32.to_le_bytes(),
        ]
        .concat();
        assert_eq!(&fat_one[..12], expected.as_slice(), "first three entries");
        assert!(
            fat_one[12..(geometry.cluster_count + 2) as usize * 4]
                .iter()
                .all(|&b| b == 0),
            "cluster entries beyond the scaffolding are free (0)"
        );
        assert!(
            fat_one[(geometry.cluster_count + 2) as usize * 4..]
                .iter()
                .all(|&b| b == 0),
            "the slack sector tail stays zero too"
        );

        // the root cluster: label entry at its head, zeros after
        let root = geometry
            .cluster_offset(geometry.root_cluster)
            .expect("cluster 2 resolves");
        volume
            .read_exact_at(root, &mut window[..32])
            .expect("root cluster head");
        assert_eq!(&window[..11], b"RUFUS      ");
        assert_eq!(window[11], 0x08, "volume label attribute");
        assert!(window[12..32].iter().all(|&b| b == 0), "entry tail zero");
        let mut rest = vec![0x77u8; (geometry.cluster_bytes() - 32) as usize];
        volume
            .read_exact_at(root + 32, &mut rest)
            .expect("root cluster tail");
        assert!(
            rest.iter().all(|&b| b == 0),
            "the root directory is otherwise empty"
        );

        // and no cluster or fat byte sits past the volume end
        assert!(
            root + geometry.cluster_bytes() <= volume.total_bytes(),
            "the root cluster stays inside the volume"
        );
    }

    #[test]
    fn formatting_twice_is_idempotent() {
        let (_, options) = sample();
        let mut volume = VecVolume::new(SIXTY_FOUR_MIB, 512).expect("64 MiB of RAM");
        format(&mut volume, options).expect("first pass");
        let first = volume.bytes().to_vec();
        format(&mut volume, options).expect("second pass");
        assert_eq!(volume.bytes(), first, "the second pass changes nothing");
    }

    #[test]
    fn hidden_sectors_land_in_the_bpb_and_a_superfloppy_writes_zero() {
        // a partitioned volume carries its start LBA at 0x1C ...
        let (_, partitioned) = sample();
        let mut volume = VecVolume::new(SIXTY_FOUR_MIB, 512).expect("64 MiB of RAM");
        format(&mut volume, partitioned).expect("the partitioned volume formats");
        let mut window = [0u8; BOOT_SECTOR_BYTES];
        volume.read_exact_at(0, &mut window).expect("boot");
        assert_eq!(&window[28..32], &2048_u32.to_le_bytes(), "partition start");

        // ... and a whole volume (no partition table) writes zero
        let superfloppy = FormatOptions {
            label: None,
            volume_id: 0x1A2B,
            ..FormatOptions::default()
        };
        let mut volume = VecVolume::new(SIXTY_FOUR_MIB, 512).expect("64 MiB of RAM");
        format(&mut volume, &superfloppy).expect("the superfloppy formats");
        volume.read_exact_at(0, &mut window).expect("boot");
        assert_eq!(&window[28..32], &[0, 0, 0, 0], "superfloppy hidden sectors");
    }

    #[test]
    fn labels_optional_from_bpb_only() {
        // no label: the BPB carries NO NAME, the root directory stays
        // fully zero (its first byte the directory-end marker 0x00)
        let options = FormatOptions {
            label: None,
            volume_id: 0x1A2B,
            hidden_sectors: 0,
            oem: bpb::DEFAULT_OEM,
        };
        let mut volume = VecVolume::new(SIXTY_FOUR_MIB, 512).expect("64 MiB of RAM");
        let geometry = format(&mut volume, &options).expect("formats");
        let mut window = [0u8; BOOT_SECTOR_BYTES];
        volume.read_exact_at(0, &mut window).expect("boot");
        assert_eq!(&window[71..82], b"NO NAME    ");
        let root = geometry.cluster_offset(ROOT_CLUSTER).expect("root cluster");
        let mut head = [0u8; 32];
        volume.read_exact_at(root, &mut head).expect("root head");
        assert!(
            head.iter().all(|&b| b == 0),
            "no entry written without a label"
        );
    }

    #[test]
    fn volume_id_zero_is_refused() {
        let mut volume = VecVolume::new(SIXTY_FOUR_MIB, 512).expect("64 MiB of RAM");
        let options = FormatOptions {
            label: None,
            volume_id: 0,
            hidden_sectors: 0,
            oem: bpb::DEFAULT_OEM,
        };
        let error = format(&mut volume, &options).expect_err("id 0 refused");
        assert!(error.to_string().contains("volume id 0"), "{error}");
        // and nothing was written: the image is still all zero
        assert!(volume.bytes().iter().all(|&b| b == 0));
    }

    /// A [`Volume`] double that re-measures itself between the reader
    /// and the first write — the shaped-wrong guard's test subject.
    struct DriftyVolume {
        inner: VecVolume,
        readings: Cell<usize>,
        /// The value every reading after the first one claims.
        drifted_bytes: u64,
    }

    impl Volume for DriftyVolume {
        fn total_bytes(&self) -> u64 {
            if self.readings.get() == 0 {
                self.readings.set(1);
                self.inner.total_bytes()
            } else {
                self.drifted_bytes
            }
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_exact_at(offset, buf)
        }

        fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }
    }

    #[test]
    fn a_sized_wrong_volume_is_refused_naming_both_readings() {
        let (_, options) = sample();
        let inner = VecVolume::new(SIXTY_FOUR_MIB, 512).expect("64 MiB of RAM");
        let drifted = SIXTY_FOUR_MIB - 4096;
        let mut volume = DriftyVolume {
            inner,
            readings: Cell::new(0),
            drifted_bytes: drifted,
        };
        let error = format(&mut volume, options).expect_err("drifted sizing refused");
        let text = error.to_string();
        assert!(text.contains(&format!("{SIXTY_FOUR_MIB}")), "{text}");
        assert!(text.contains(&format!("{drifted}")), "{text}");
        assert!(text.contains("reported"), "{text}");
    }

    /// A [`Volume`] whose writes always fail.
    struct FailingVolume {
        total_bytes: u64,
        sector_size: u32,
    }

    impl Volume for FailingVolume {
        fn total_bytes(&self) -> u64 {
            self.total_bytes
        }

        fn read_exact_at(&self, _offset: u64, buf: &mut [u8]) -> Result<()> {
            buf.copy_from_slice(vec![0u8; buf.len()].as_slice());
            Ok(())
        }

        fn write_all_at(&mut self, _offset: u64, _buf: &[u8]) -> Result<()> {
            Err(CoreError::io(
                "<fat32 volume>",
                io::Error::from(io::ErrorKind::StorageFull),
            ))
        }

        fn sector_size(&self) -> u32 {
            self.sector_size
        }
    }

    #[test]
    fn a_failing_volume_surfaces_its_error_without_a_panic() {
        let (_, options) = sample();
        let mut volume = FailingVolume {
            total_bytes: SIXTY_FOUR_MIB,
            sector_size: 512,
        };
        let result = format(&mut volume, options);
        let error = result.expect_err("the failing volume fails the format");
        let text = error.to_string();
        assert!(text.contains("I/O error at '<fat32 volume>'"), "{text}");
    }
}
