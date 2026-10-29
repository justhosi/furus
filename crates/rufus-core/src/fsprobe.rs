//! Superblock recognition from raw device bytes (S05).
//!
//! [`probe`] answers one question per area: "what kind of filesystem (or
//! volume manager) lives here?" — the same check Rufus makes before it
//! dares to propose an erase. It is deliberately *not* a filesystem
//! reader: the magic checks are just sharp enough that S05 can (a)
//! recognise the four systems the rewrite cannot create (LVM2, btrfs,
//! XFS, ZFS — PLAN §9-S05 "the last four only to *recognise and
//! refuse*") and (b) tell the user what an erase would destroy.
//!
//! Check order is pinned by tests where it matters: UDF before
//! ISO9660, because a UDF bridge image also contains the `CD001`
//! descriptor and must report as UDF. The remaining families have
//! disjoint magics and windows, so their relative order is conventional
//! (NTFS/exFAT/FAT before ext, then per the S05 deliverable list).
//!
//! Everything works on byte windows the caller supplies — short or
//! empty windows fail their magic check and never panic, matching the
//! `#![forbid(unsafe_code)]` crate rule and the S04 school of "a
//! missing attribute is normal, not an error".

use serde::Serialize;

use crate::partition::MBR_SIGNATURE;

/// UDF/ISO volume descriptors are 2048 bytes apart; descriptor `n` sits
/// at byte `n * 2048`, so the probed descriptors 16..=23 span
/// `0x8000..0xC000`. A whole [`Sample::from_prefix`]-style prefix (64
/// KiB per the [`Sample`] contract) covers that window; shorter
/// prefixes just match nothing (graceful degradation).
const OPTICAL_SECTOR: u64 = 2048;
/// The first and last of the descriptors probed for UDF magics.
const OPTICAL_DESCRIPTOR_FIRST: u64 = 16;
const OPTICAL_DESCRIPTOR_LAST: u64 = 23;
/// Offsets of the FAT OEM tags (`FATxx   ` in the boot record's OEM
/// block; `FAT32   ` lives inside the extended boot record).
const FAT_MAGIC_OFFSET: usize = 54;
const FAT32_MAGIC_OFFSET: usize = 82;
/// Where the FAT BPB stores its bytes-per-sector `u16`.
const FAT_BPB_BYTES_PER_SECTOR: usize = 11;
/// Absolute position of the boot-sector signature, shared with MBR
/// disks ([`MBR_SIGNATURE`]).
const BOOT_SIGNATURE_OFFSET: usize = 510;
/// ext magic (`u16` `0xEF53`) and the two feature words, all absolute.
const EXT_MAGIC_OFFSET: usize = 0x438;
const EXT_COMPAT_OFFSET: usize = 0x5C;
const EXT_INCOMPAT_OFFSET: usize = 0x60;
/// ext feature bits: `has_journal` in `s_feature_compat`, and the
/// ext4-only bits in `s_feature_incompat` (extents, 64bit, flex_bg,
/// ea_inode).
const EXT_FEATURE_JOURNAL: u32 = 0x4;
const EXT_FEATURE_INCOMPAT_EXT4: u32 = 0x40 | 0x80 | 0x200 | 0x400;
/// A swap signature is ten bytes sitting at the end of the first OS
/// page: offset 4086 for 4 KiB pages, 8182 for 8 KiB ones.
const SWAP_MAGIC_OFFSETS: [usize; 2] = [4096 - 10, 8192 - 10];
/// Spellings of the swap signature: the modern `SWAPSPACE2` and the
/// historical `SWAP-SPACE`. Both are accepted at **both** page ends —
/// swap is erasable data, so a generous accept-list costs nothing (a
/// misplaced magic must then be near-end-of-page, which the offsets
/// bound tightly).
const SWAP_MAGIC_SPACE2: &[u8; 10] = b"SWAPSPACE2";
const SWAP_MAGIC_DASH: &[u8; 10] = b"SWAP-SPACE";
/// LVM2 label: `LABELONE` at the start of the second sector plus the
/// `LVM2 001` type/version tag inside the same label record.
const LVM2_LABEL_ID_OFFSET: usize = 512;
const LVM2_TYPE_ID_OFFSET: usize = 536;

/// One recognised filesystem or volume-manager kind.
///
/// [`FsKind::as_str`] spells each variant exactly like the `snake_case`
/// JSON tag above (`"fat12"`, `"lvm2"`, ...), so human CLI output and
/// machine output never drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FsKind {
    /// FAT12 (floppy legacy, still around on tiny boot media).
    Fat12,
    /// FAT16.
    Fat16,
    /// FAT32 — what Rufus creates for its FAT targets.
    Fat32,
    /// NTFS.
    Ntfs,
    /// exFAT.
    Exfat,
    /// ext2 (no journal bit).
    Ext2,
    /// ext3 (journal, no ext4-only features).
    Ext3,
    /// ext4 (ext4-only incompatible features).
    Ext4,
    /// UDF (Rufus writes it; bridge images report here rather than ISO).
    Udf,
    /// ISO9660 (plain CD descriptor; Joliet variants report the same).
    Iso9660,
    /// Linux swap area.
    Swap,
    /// LVM2 physical volume — recognised only to refuse erasing it.
    Lvm2,
    /// Btrfs — recognised only to refuse erasing it.
    Btrfs,
    /// XFS — recognised only to refuse erasing it.
    Xfs,
    /// ZFS label — recognised only to refuse erasing it.
    Zfs,
}

impl FsKind {
    /// Lowercase ASCII slug, identical to the `snake_case` JSON tag of
    /// the variant above.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fat12 => "fat12",
            Self::Fat16 => "fat16",
            Self::Fat32 => "fat32",
            Self::Ntfs => "ntfs",
            Self::Exfat => "exfat",
            Self::Ext2 => "ext2",
            Self::Ext3 => "ext3",
            Self::Ext4 => "ext4",
            Self::Udf => "udf",
            Self::Iso9660 => "iso9660",
            Self::Swap => "swap",
            Self::Lvm2 => "lvm2",
            Self::Btrfs => "btrfs",
            Self::Xfs => "xfs",
            Self::Zfs => "zfs",
        }
    }

    /// True for the systems S05 only recognises in order to refuse
    /// erasing them — the write path (S07/S08) must never wipe a volume
    /// manager's metadata; a dedicated tool has to do that job.
    #[must_use]
    pub fn refusable(self) -> bool {
        matches!(self, Self::Lvm2 | Self::Btrfs | Self::Xfs | Self::Zfs)
    }
}

/// The three byte windows of one area the probe looks at.
///
/// `prefix` is the first 64 KiB of the area: it holds MBR/BPB and the
/// boot signature, the ext superblock at `0x438`, swap page 0 (and, for
/// 8 KiB pages, page 1 up to `0x2000`), the LVM2 label at 512, and the
/// whole volume-recognition sequence at `0x8000..0xC000` (descriptors
/// 16..=23 at 2048-byte pitch) that UDF and ISO9660 need. `at_64k` and
/// `at_128k` are the two superblock windows that live beyond what a
/// prefix should want to hold: btrfs at `+0x10000` and the ZFS label at
/// `+0x20000`, both 1 KiB nominally but read as far as the caller got.
///
/// A caller that could not read a window passes an empty slice — the
/// corresponding checks simply never match, they never invent bytes.
/// [`Sample::from_prefix`] supplies exactly the prefix with empty upper
/// windows (a 64-KiB prefix cannot reach `0x10000` anyway); the S05
/// inspection half hand-builds the struct from three direct reads.
#[derive(Debug, Clone, Copy)]
pub struct Sample<'a> {
    /// The first 64 KiB (`0x00000..0x10000`): MBR/BPB, ext superblock
    /// at `0x438`, swap page 0, LVM2 label at 512, and the ISO9660/UDF
    /// volume recognition sequence at `0x8000..0xC000`.
    pub prefix: &'a [u8],
    /// 1 KiB read at `0x10000`; the btrfs superblock magic `_BHRfS_M`
    /// sits at window offset `+0x40`.
    pub at_64k: &'a [u8],
    /// 1 KiB read at `0x20000`; the ZFS label magic `0x00bab10c` (a
    /// little-endian `u64`) sits at window offset `+0`.
    pub at_128k: &'a [u8],
}

impl<'a> Sample<'a> {
    /// A sample that can only probe prefix-relative layouts: the
    /// leading bytes as given, and empty upper windows. A 64-KiB prefix
    /// (the window contract above) does not reach `0x10000`, so there
    /// is nothing honest to carve for btrfs or ZFS from it — callers
    /// that have those windows supply them directly.
    #[must_use]
    pub fn from_prefix(prefix: &'a [u8]) -> Self {
        Self {
            prefix,
            at_64k: &[],
            at_128k: &[],
        }
    }
}

/// Does `buf` hold `magic` starting at `at`? Built on `get`, so a short
/// buffer answers false instead of panicking; the offset arithmetic is
/// checked because offsets are caller-supplied.
fn matches_at(buf: &[u8], at: usize, magic: &[u8]) -> bool {
    magic.iter().enumerate().all(|(index, expected)| {
        at.checked_add(index).and_then(|offset| buf.get(offset)) == Some(expected)
    })
}

/// Read one little-endian `u16` at `at` (no panicking indexing).
fn u16_le(buf: &[u8], at: usize) -> Option<u16> {
    let bytes = buf.get(at..at.checked_add(2)?)?;
    let unit: [u8; 2] = bytes.try_into().ok()?;
    Some(u16::from_le_bytes(unit))
}

/// Read one little-endian `u32` at `at`.
fn u32_le(buf: &[u8], at: usize) -> Option<u32> {
    let bytes = buf.get(at..at.checked_add(4)?)?;
    let unit: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_le_bytes(unit))
}

/// Read one little-endian `u64` at `at` (the ZFS label magic width).
fn u64_le(buf: &[u8], at: usize) -> Option<u64> {
    let bytes = buf.get(at..at.checked_add(8)?)?;
    let unit: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_le_bytes(unit))
}

/// UDF: `BEA01` or `NSR0` at the start of one of the 2048-byte-aligned
/// volume-recognition descriptors 16..=23.
fn probe_udf(prefix: &[u8]) -> bool {
    (OPTICAL_DESCRIPTOR_FIRST..=OPTICAL_DESCRIPTOR_LAST).any(|descriptor| {
        let at = usize::try_from(descriptor * OPTICAL_SECTOR).unwrap_or(usize::MAX);
        matches_at(prefix, at, b"BEA01") || matches_at(prefix, at, b"NSR0")
    })
}

/// Plain ISO9660: `CD001` one byte into descriptor 16 (offset 0 holds
/// the descriptor-type byte).
fn probe_iso9660(prefix: &[u8]) -> bool {
    matches_at(prefix, 0x8001, b"CD001")
}

/// Microsoft family: NTFS and exFAT by an 8-byte tag at offset 3; FAT
/// by its OEM tag (54: FAT12/FAT16, 82: FAT32) — but only with a sane
/// BPB and the boot signature in place, because the tag alone is a few
/// ASCII letters that random text can carry.
fn probe_microsoft(prefix: &[u8]) -> Option<FsKind> {
    if matches_at(prefix, 3, b"NTFS    ") {
        return Some(FsKind::Ntfs);
    }
    if matches_at(prefix, 3, b"EXFAT   ") {
        return Some(FsKind::Exfat);
    }
    let fat_kind = if matches_at(prefix, FAT_MAGIC_OFFSET, b"FAT12   ") {
        Some(FsKind::Fat12)
    } else if matches_at(prefix, FAT_MAGIC_OFFSET, b"FAT16   ") {
        Some(FsKind::Fat16)
    } else if matches_at(prefix, FAT32_MAGIC_OFFSET, b"FAT32   ") {
        Some(FsKind::Fat32)
    } else {
        None
    };
    let kind = fat_kind?;
    // BPB sanity: sectors must read, be a power of two inside the BIOS
    // range, and the format tools must have set the boot signature.
    let bytes_per_sector = u16_le(prefix, FAT_BPB_BYTES_PER_SECTOR)?;
    if !(512..=4096).contains(&bytes_per_sector) || !bytes_per_sector.is_power_of_two() {
        return None;
    }
    if prefix.get(BOOT_SIGNATURE_OFFSET..BOOT_SIGNATURE_OFFSET + 2) != Some(&MBR_SIGNATURE[..]) {
        return None;
    }
    Some(kind)
}

/// ext2/3/4: the `0xEF53` superblock magic, then the feature words —
/// no journal bit in `s_feature_compat` → ext2; otherwise any
/// ext4-only incompatible feature → ext4; else ext3. Unreadable
/// feature words (physically short buffer) count as 0, which makes the
/// answer degrade to plain ext2 instead of an invented ext4 claim.
fn probe_ext(prefix: &[u8]) -> Option<FsKind> {
    if u16_le(prefix, EXT_MAGIC_OFFSET) != Some(0xEF53) {
        return None;
    }
    let compat = u32_le(prefix, EXT_COMPAT_OFFSET).unwrap_or(0);
    if compat & EXT_FEATURE_JOURNAL == 0 {
        return Some(FsKind::Ext2);
    }
    let incompat = u32_le(prefix, EXT_INCOMPAT_OFFSET).unwrap_or(0);
    if incompat & EXT_FEATURE_INCOMPAT_EXT4 != 0 {
        Some(FsKind::Ext4)
    } else {
        Some(FsKind::Ext3)
    }
}

/// Swap area: a ten-byte signature at the end of the first OS page —
/// 4086 for 4 KiB pages, 8182 for 8 KiB ones. Both historical
/// spellings match at either page end (see the constants); a magic at
/// any other offset does not count as an area.
fn probe_swap(prefix: &[u8]) -> bool {
    SWAP_MAGIC_OFFSETS.iter().any(|&at| {
        matches_at(prefix, at, SWAP_MAGIC_SPACE2) || matches_at(prefix, at, SWAP_MAGIC_DASH)
    })
}

/// LVM2 physical volume: both halves of the label must be present, so a
/// stray `LABELONE` fragment alone does not count.
fn probe_lvm2(prefix: &[u8]) -> bool {
    matches_at(prefix, LVM2_LABEL_ID_OFFSET, b"LABELONE")
        && matches_at(prefix, LVM2_TYPE_ID_OFFSET, b"LVM2 001")
}

/// Recognise what the area holds. `None` when nothing recognisable is
/// present — which, for a blank stick, is the expected answer and no
/// failure.
#[must_use]
pub fn probe(sample: &Sample<'_>) -> Option<FsKind> {
    if probe_udf(sample.prefix) {
        return Some(FsKind::Udf);
    }
    if probe_iso9660(sample.prefix) {
        return Some(FsKind::Iso9660);
    }
    if let Some(kind) = probe_microsoft(sample.prefix) {
        return Some(kind);
    }
    if let Some(kind) = probe_ext(sample.prefix) {
        return Some(kind);
    }
    if probe_swap(sample.prefix) {
        return Some(FsKind::Swap);
    }
    if probe_lvm2(sample.prefix) {
        return Some(FsKind::Lvm2);
    }
    if matches_at(sample.at_64k, 0x40, b"_BHRfS_M") {
        return Some(FsKind::Btrfs);
    }
    if matches_at(sample.prefix, 0, b"XFSB") {
        return Some(FsKind::Xfs);
    }
    // ZFS labels start with a little-endian `u64` `0x00bab10c`, the
    // BSD-label magic every vdev label carries at its own offset 0.
    if u64_le(sample.at_128k, 0) == Some(0x00BA_B10C) {
        return Some(FsKind::Zfs);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::FsKind;
    use super::Sample;
    use super::probe;

    /// A zero-filled buffer of `len` bytes (plus optional splices).
    fn zeros(len: usize) -> Vec<u8> {
        vec![0u8; len]
    }

    /// Expect the probe to name `want`, with a readable failure message.
    fn assert_probe(buffer: &[u8], want: Option<FsKind>) {
        let got = probe(&Sample::from_prefix(buffer));
        assert_eq!(got, want, "buffer len {}", buffer.len());
    }

    // ------------------------------------------------------------------
    // Microsoft family
    // ------------------------------------------------------------------

    #[test]
    fn ntfs_and_exfat_match_by_their_byte3_tags() {
        let mut ntfs = zeros(16);
        ntfs[3..11].copy_from_slice(b"NTFS    ");
        assert_probe(&ntfs, Some(FsKind::Ntfs));

        let mut exfat = zeros(16);
        exfat[3..11].copy_from_slice(b"EXFAT   ");
        assert_probe(&exfat, Some(FsKind::Exfat));

        // Wrong tag a byte off: magic, not a filesystem.
        let mut hostile = zeros(16);
        hostile[3..11].copy_from_slice(b"NTFX    ");
        assert_probe(&hostile, None);
    }

    /// A FAT boot sector with the given OEM tag location, BPB size and
    /// (optional) boot signature.
    fn fat_sector(
        magic_at: usize,
        magic: &[u8; 8],
        bytes_per_sector: u16,
        signed: bool,
    ) -> Vec<u8> {
        let mut buffer = vec![0u8; 512];
        buffer[magic_at..magic_at + 8].copy_from_slice(magic);
        buffer[11..13].copy_from_slice(&bytes_per_sector.to_le_bytes());
        if signed {
            buffer[510..512].copy_from_slice(&super::MBR_SIGNATURE);
        }
        buffer
    }

    #[test]
    fn fat_tags_sort_into_their_kinds() {
        for (magic_at, magic, want) in [
            (54, b"FAT12   ", FsKind::Fat12),
            (54, b"FAT16   ", FsKind::Fat16),
            (82, b"FAT32   ", FsKind::Fat32),
        ] {
            let sector = fat_sector(magic_at, magic, 512, true);
            assert_probe(&sector, Some(want));
        }
    }

    #[test]
    fn fat_needs_a_sane_bpb_and_the_boot_signature() {
        // A plausible tag but a BPB size that is not a power of two.
        let sector = fat_sector(82, b"FAT32   ", 768, true);
        assert_probe(&sector, None);
        // Power of two, but below the BIOS range floor of 512.
        let small = fat_sector(82, b"FAT32   ", 256, true);
        assert_probe(&small, None);
        // Power of two in range, above the range ceiling of 4096.
        let huge = fat_sector(82, b"FAT32   ", 8192, true);
        assert_probe(&huge, None);
        // Everything sane, but the 0x55AA boot signature is missing.
        let unsigned = fat_sector(82, b"FAT32   ", 512, false);
        assert_probe(&unsigned, None);
        // Same three shapes for the FAT16 tag at 54.
        assert_probe(&fat_sector(54, b"FAT16   ", 1024, false), None);
    }

    // ------------------------------------------------------------------
    // ext family
    // ------------------------------------------------------------------

    /// An ext superblock with the two feature words set as given.
    fn ext_superblock(compat: u32, incompat: u32) -> Vec<u8> {
        let mut buffer = vec![0u8; 0x800];
        buffer[0x438..0x43A].copy_from_slice(&0xEF53u16.to_le_bytes());
        buffer[0x5C..0x60].copy_from_slice(&compat.to_le_bytes());
        buffer[0x60..0x64].copy_from_slice(&incompat.to_le_bytes());
        buffer
    }

    #[test]
    fn ext_feature_bits_sort_the_three_generations() {
        // No journal bit: ext2, whatever the incompatible bits say.
        assert_probe(&ext_superblock(0x3, 0x400), Some(FsKind::Ext2));
        // Journal, no ext4-only incompatible feature: ext3.
        assert_probe(&ext_superblock(0x2C, 0x2), Some(FsKind::Ext3));
        // Any of the four ext4-only bits promotes to ext4.
        for bit in [0x40u32, 0x80, 0x200, 0x400] {
            assert_probe(&ext_superblock(0x2C, bit), Some(FsKind::Ext4));
        }
    }

    #[test]
    fn ext_short_or_wrong_magic_buffers_never_match() {
        // Barely-tiny buffer: the magic position is not even reached.
        assert_probe(&zeros(0x20), None);
        // Length enough for the magic words to be read; wrong magic.
        let mut almost = vec![0u8; 0x800];
        almost[0x438..0x43A].copy_from_slice(&0xEF50u16.to_le_bytes());
        assert_probe(&almost, None);
    }

    // ------------------------------------------------------------------
    // Optical family (UDF before ISO9660) and the far windows
    // ------------------------------------------------------------------

    #[test]
    fn udf_recognition_sequence_matching() {
        // `BEA01` in the first probed descriptor (16) — inside a full
        // 64-KiB prefix, the contract the real reader supplies.
        let mut buffer = zeros(0x10000);
        buffer[16 * 2048..16 * 2048 + 5].copy_from_slice(b"BEA01");
        assert_probe(&buffer, Some(FsKind::Udf));

        // `NSR0` (NSR02/NSR03 share the prefix) in a later descriptor.
        let mut nsr = zeros(0x10000);
        nsr[19 * 2048..19 * 2048 + 4].copy_from_slice(b"NSR0");
        assert_probe(&nsr, Some(FsKind::Udf));

        // Nothing at the recognisable descriptors (plain data prefix).
        assert_probe(&zeros(0x10000), None);
    }

    #[test]
    fn udf_wins_over_plain_iso9660_on_bridge_images() {
        let mut bridge = zeros(0x10000);
        bridge[0x8001..0x8006].copy_from_slice(b"CD001"); // ISO descriptor 16
        bridge[0x8800..0x8804].copy_from_slice(b"NSR0"); // UDF descriptor 17
        assert_probe(&bridge, Some(FsKind::Udf));

        // And without any UDF magic, the ISO descriptor counts on its own.
        let mut plain = zeros(0x10000);
        plain[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_probe(&plain, Some(FsKind::Iso9660));
    }

    #[test]
    fn optical_scan_starts_at_descriptor_16_not_earlier() {
        // A bare 16 KiB prefix has not even reached the volume
        // recognition sequence at 0x8000: a `CD001` near the top of it
        // must be ignored, and the probe must answer None, never a
        // fabricated ISO9660.
        let mut short_prefix = zeros(0x4000);
        short_prefix[1..6].copy_from_slice(b"CD001");
        assert_probe(&short_prefix, None);
    }

    // ------------------------------------------------------------------
    // Swap, LVM2 and the far-window filesystems
    // ------------------------------------------------------------------

    /// The full swap contract: **both** magics are accepted at **both**
    /// page ends (4086 and 8182) — the kernel parks the signature at
    /// the end of whatever page size it used, and either spelling can
    /// appear with either page size (the modern `SWAPSPACE2` and the
    /// historical `SWAP-SPACE` are independent of that choice). Swap is
    /// erasable data, so the generous accept-list is safe; a magic at
    /// any *other* offset is not an area.
    #[test]
    fn swap_accepts_both_magics_at_both_page_ends_only() {
        for (page_len, magic_offset) in [(4096usize, 4086usize), (8192, 8182)] {
            for magic in [b"SWAPSPACE2", b"SWAP-SPACE"] {
                let mut page = zeros(page_len);
                let magic_len = magic.len();
                page[magic_offset..magic_offset + magic_len].copy_from_slice(magic);
                assert_probe(&page, Some(FsKind::Swap));
            }
        }

        // Real negatives: ten swap-looking bytes anywhere else are just
        // bytes — past a page end, and before one.
        let mut past_the_4k_page_end = zeros(8192);
        past_the_4k_page_end[4096..4106].copy_from_slice(b"SWAPSPACE2");
        assert_probe(&past_the_4k_page_end, None);

        let mut deep_inside_the_page = zeros(4096);
        deep_inside_the_page[0x400..0x40A].copy_from_slice(b"SWAP-SPACE");
        assert_probe(&deep_inside_the_page, None);
    }

    #[test]
    fn lvm2_needs_both_label_halves() {
        let mut full = zeros(600);
        full[512..520].copy_from_slice(b"LABELONE");
        full[536..544].copy_from_slice(b"LVM2 001");
        assert_probe(&full, Some(FsKind::Lvm2));

        let mut half = zeros(600);
        half[512..520].copy_from_slice(b"LABELONE");
        assert_probe(&half, None);
    }

    /// Hand-built sample: prefix plus explicit windows, the shape the
    /// S05 inspection half constructs from three direct reads.
    fn windows_sample<'a>(prefix: &'a [u8], at_64k: &'a [u8], at_128k: &'a [u8]) -> Sample<'a> {
        Sample {
            prefix,
            at_64k,
            at_128k,
        }
    }

    #[test]
    fn far_window_filesystems() {
        // btrfs superblock magic at window offset 0x40 (absolute
        // 0x10040); the prefix itself stays blank.
        let prefix = zeros(0x10000);
        let empty: Vec<u8> = Vec::new();
        let mut btrfs_window = vec![0u8; 1024];
        btrfs_window[0x40..0x48].copy_from_slice(b"_BHRfS_M");
        let sample = windows_sample(&prefix, &btrfs_window, &empty);
        assert_eq!(probe(&sample), Some(FsKind::Btrfs));

        // XFS magic right at 0 in the prefix (needs no window at all).
        assert_probe(b"XFSB", Some(FsKind::Xfs));

        // ZFS label magic: the LE u64 0x00bab10c at window offset 0
        // (absolute 0x20000).
        let mut zfs_window = vec![0u8; 1024];
        zfs_window[0..8].copy_from_slice(&0x00BA_B10Cu64.to_le_bytes());
        let sample = windows_sample(&prefix, &empty, &zfs_window);
        assert_eq!(probe(&sample), Some(FsKind::Zfs));

        // A near-miss label magic one bit off must not classify as ZFS.
        let mut decoy_window = vec![0u8; 1024];
        decoy_window[0..8].copy_from_slice(&0x00BA_B10Du64.to_le_bytes());
        let sample = windows_sample(&prefix, &empty, &decoy_window);
        assert_eq!(probe(&sample), None);
    }

    #[test]
    fn from_prefix_supplies_only_the_prefix_and_empty_windows() {
        assert_probe(&zeros(512), None);
        let prefix = zeros(0x10000);
        let sample = Sample::from_prefix(&prefix);
        assert_eq!(sample.prefix.len(), 0x10000);
        // from_prefix never fabricates windows; the caller opts in.
        assert_eq!(sample.at_64k.len(), 0);
        assert_eq!(sample.at_128k.len(), 0);
        assert!(
            probe(&sample).is_none(),
            "a bare prefix reaches nothing at 0x10000/0x20000"
        );
    }

    // ------------------------------------------------------------------
    // Negative set, kind tags, refusable
    // ------------------------------------------------------------------

    #[test]
    fn empty_and_random_buffers_probe_to_none() {
        assert_probe(&[], None);
        // Hundreds of ASCII `a`s: no tag anywhere, no BPB, nothing lands.
        assert_probe(&vec![b'a'; 512], None);
        // Plausible mental fluff: lengths nothing, contents zeroed...
        assert_probe(&zeros(0x10000), None);
    }

    #[test]
    fn as_str_spells_the_snake_case_json_tags() {
        let kinds = [
            (FsKind::Fat12, "fat12"),
            (FsKind::Fat16, "fat16"),
            (FsKind::Fat32, "fat32"),
            (FsKind::Ntfs, "ntfs"),
            (FsKind::Exfat, "exfat"),
            (FsKind::Ext2, "ext2"),
            (FsKind::Ext3, "ext3"),
            (FsKind::Ext4, "ext4"),
            (FsKind::Udf, "udf"),
            (FsKind::Iso9660, "iso9660"),
            (FsKind::Swap, "swap"),
            (FsKind::Lvm2, "lvm2"),
            (FsKind::Btrfs, "btrfs"),
            (FsKind::Xfs, "xfs"),
            (FsKind::Zfs, "zfs"),
        ];
        for (kind, tag) in kinds {
            // serde_json is not a dev-dependency of this crate (PLAN §5
            // forbids another one), so the JSON tag is pinned through
            // the identical literal: `rename_all = "snake_case"` above
            // derives exactly this spelling from each variant name.
            // (Same technique as the transport tags in rufus_linux.)
            assert_eq!(kind.as_str(), tag, "{kind:?} tag");
        }
    }

    #[test]
    fn refusable_is_exactly_the_four_volume_managers() {
        for (kind, want) in [
            (FsKind::Fat12, false),
            (FsKind::Fat16, false),
            (FsKind::Fat32, false),
            (FsKind::Ntfs, false),
            (FsKind::Exfat, false),
            (FsKind::Ext2, false),
            (FsKind::Ext3, false),
            (FsKind::Ext4, false),
            (FsKind::Udf, false),
            (FsKind::Iso9660, false),
            (FsKind::Swap, false),
            (FsKind::Lvm2, true),
            (FsKind::Btrfs, true),
            (FsKind::Xfs, true),
            (FsKind::Zfs, true),
        ] {
            assert_eq!(kind.refusable(), want, "{kind:?} refusable");
        }
    }
}
