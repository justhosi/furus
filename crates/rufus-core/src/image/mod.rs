//! Container detection and header validation for the image formats
//! Rufus accepts (S15, slice 3 of 4).
//!
//! [`detect`] sniffs the container family by magic bytes over any
//! [`Volume`](crate::fs::Volume): size-guarded probes that never panic
//! on short files. [`open_image`] opens a regular file read-only,
//! detects it, validates the container header for the families that
//! carry one (VHD, VHDX, FFU, qcow2) and returns the [`Image`]: the
//! kind, the virtual size and the logical contents (a fixed VHD
//! presents file bytes `0..current_size`, without its footer; every
//! other family maps its blocks or clusters the same way).
//!
//! The probe order below is deliberate and pinned by tests: VHDX
//! (`vhdxfile` at 0), FFU (`ImageFlash` at 0, or the security header
//! `SignedImage ` at 4 of a security-first file), qcow2 (`QFI\xfb` at
//! 0), WIM (`MSWIM\0\0\0` at 0), the compression magics (xz, zstd,
//! bzip2, gzip), PE (`MZ` at 0), VHD (`conectix` at size minus 512),
//! ISO (`CD001` at 0x8001). Offset-0 magics come first because they
//! describe the outermost framing at byte 0; the two offset probes
//! come last because they read away from byte 0. VHD precedes ISO
//! because a fixed VHD converted from an ISO payload (`qemu-img
//! convert -O vpc`) carries both signals — the ISO magic in its
//! payload at 0x8001 and the footer at its end — and the outer
//! container must win, otherwise the plan would raw-copy the
//! container. No other pair shadows: the offset-0 magics are pairwise
//! disjoint (none is a prefix of another, and `MSWIM`/`MZ` differ in
//! the second byte), so their relative order cannot misfire, and the
//! VHD/ISO pair is the only one where one valid container routinely
//! embeds the other's magic. A file with no match and non-zero
//! length is [`ImageKind::Raw`]; an empty file, or one shorter than
//! every probe, is [`ImageKind::Unknown`]. Once a magic matches, the
//! kind is committed: a truncated or self-contradictory container fails
//! with a specific message, it never falls back to [`ImageKind::Raw`].
//!
//! *Measured* — every on-disk fact below was read off real `qemu-img
//! 11.1.3` output inside `archlinux:latest` (fixed and dynamic `-f
//! vpc`, `-f vhdx` and `-f qcow2` images at 64 MiB; see the slice
//! report for the container commands and the `qemu-img info` output
//! the validator outputs were compared against):
//!
//! * VHD: the 512-byte footer at size minus 512 reads `conectix`,
//!   format version `0x00010000`, data offset `0xFFFFFFFFFFFFFFFF` for
//!   fixed and the dynamic-header offset for dynamic, creator `qemu`
//!   version `0x00050003` on host `Wi2k`, matching original and current
//!   sizes (`0x04004000` for the 64 MiB request), geometry
//!   964/8/17, disk type 2 (fixed) or 3 (dynamic); the checksum is the
//!   one's complement of the 512-byte sum with the checksum field
//!   zeroed, verified against both files. The dynamic header at the
//!   footer's data offset reads `cxsparse`, header version
//!   `0x00010000`, a 2 MiB block size, 33 table entries (one more than
//!   the 32 full blocks the size needs) with the BAT right after it,
//!   and the same one's-complement checksum over its 1024 bytes.
//! * VHDX: `vhdxfile` plus a UTF-16 creator at 0, a `head` header at
//!   both 64 KiB and 128 KiB (sequence numbers differing by one, a zero
//!   log GUID meaning a clean log, log version 0, file version 1, a
//!   1 MiB log at a 1 MiB offset), and a `regi` region table at 192 KiB
//!   with two entries (the BAT and metadata GUIDs at 2 MiB and 3 MiB,
//!   1 MiB each). Both header checksums and the region-table checksum
//!   are CRC-32C over the whole 4 KiB / 64 KiB block with the checksum
//!   field zeroed, verified against the file; the region GUID bytes
//!   agree with the known values in QEMU's `block/vhdx.h`.
//! * qcow2: `QFI\xfb`, version 3, a zero backing-file offset, 16
//!   cluster bits (64 KiB clusters), the 64 MiB virtual size, one L1
//!   entry whose 8-byte table sits exactly at the file end.
//!
//! *Inferred* — spec or source text with no real-image sample behind
//! it on this host (no FFU producer and no Hyper-V exist here):
//!
//! * FFU: the header triple (image, security, store) follows the
//!   `IMAGE_HEADER` / `SECURITY_HEADER` / `STORE_HEADER` shapes and the
//!   `cbSize` values 24 / 32 that two published real-DISM logs show
//!   (`Size = 24`, `Size = 32`, `ManifestLength`, `ChunkSizeInKB =
//!   128`, `AlgorithmId = 32780`, `FullFlashMajorVersion = 2 and 3`,
//!   `BlockSize = 131072`); the security-first file order follows
//!   Rufus's own `vhd.c` (which probes `SignedImage ` at offset 4) and
//!   the DISM log order, while the `ImageFlash`-first order keeps the
//!   S03 detection working — both validate the same store header from
//!   byte 56 on. There is no whole-header checksum field to verify
//!   (integrity rides in the catalog and hash table, whose windows are
//!   bounds-checked here); payload hash verification belongs to slice
//!   4. `FullFlashMajorVersion` 1 is accepted for phone-era files, 0
//!   and 4+ are refused.
//! * VHD details no producer sample pins down: the creator-application
//!   printable-ASCII rule (every known producer writes a short ASCII
//!   tag), the refusal of a zero BAT offset (it would alias the footer
//!   copy dynamic disks carry at 0), and the acceptance of fixed (2)
//!   and dynamic (3) with differencing (4) refused for needing its
//!   parent. The footer copy at 0, the timestamp, the geometry and the
//!   parent locators are parsed nowhere on purpose.
//! * VHDX details: the refusal of a dirty log (a non-zero log GUID
//!   needs log replay, which slice 4 does not implement yet) and of
//!   unknown *required* region entries (QEMU fails those too); the
//!   per-entry file-offset 1 MiB alignment follows QEMU's `vhdx.h`.
//! * qcow2 details: the refusal of a zero L1 offset (it would alias the
//!   header) and of a zero L1 size; the version-3 tail fields
//!   (incompatible features, header length) are parsed nowhere yet and
//!   belong to slice 4.
//!
//! What this slice owns, file by file:
//!
//! * [`vhd`] — the VHD footer, the dynamic header (`cxsparse`) and the
//!   logical reader (fixed disks as `0..current_size`, dynamic disks
//!   through the BAT and the per-block sector bitmaps).
//! * [`vhdx`] — the VHDX file identifier, both headers, the region
//!   table, the metadata table and the BAT reader, plus the local
//!   CRC-32C (Castagnoli) the format checksums with — the crate's
//!   existing CRC-32 (IEEE, used by GPT) is the wrong polynomial, so
//!   it is not reused.
//! * [`ffu`] — the FFU header triple in both file orders and the
//!   store-table reader (inferred: no sample exists on this host).
//! * [`qcow2`] — the qcow2 header and the L1/L2 cluster reader.

use std::path::Path;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::FileVolume;
use crate::fs::Volume;

pub mod ffu;
pub mod qcow2;
pub mod vhd;
pub mod vhdx;

/// Re-exported container family so callers need only this module. The
/// enum itself (including the `qcow2` variant this slice adds) lives in
/// `rufus-proto`: there is exactly one definition.
pub use rufus_proto::ImageKind;

/// `vhdxfile` at offset 0.
const VHDX_MAGIC: [u8; 8] = *b"vhdxfile";
/// `QFI\xfb` at offset 0 (qcow2).
const QCOW2_MAGIC: [u8; 4] = [0x51, 0x46, 0x49, 0xFB];
/// `MSWIM\0\0\0` at offset 0 (a WIM or ESD).
const WIM_MAGIC: [u8; 8] = *b"MSWIM\0\0\0";
/// xz stream header at offset 0.
const XZ_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
/// zstd frame magic at offset 0.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
/// bzip2 stream header at offset 0.
const BZIP2_MAGIC: [u8; 3] = *b"BZh";
/// gzip stream header at offset 0.
const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];
/// Windows PE image header at offset 0.
const PE_MAGIC: [u8; 2] = *b"MZ";
/// VHD footer magic at size minus 512.
const VHD_MAGIC: [u8; 8] = *b"conectix";
/// ISO9660 volume-descriptor magic at 0x8001.
const ISO_MAGIC: [u8; 5] = *b"CD001";

/// Longest offset-0 probe window [`detect`] reads: the security-first
/// FFU probe needs bytes 0..16.
const HEAD_LEN: u64 = 16;
/// Shortest magic any probe looks for (gzip, PE): a non-empty file
/// shorter than this matched no probe because none could apply.
const SHORTEST_MAGIC: u64 = 2;
/// Offset of the ISO9660 magic inside sector 16.
const ISO_MAGIC_OFFSET: u64 = 0x8001;
/// Length of the VHD footer.
const VHD_FOOTER_LEN: u64 = 512;

/// Detect the image container kind by magic only (see the module
/// header for the probe order).
///
/// Size-guarded and never panicking on short files: every probe reads
/// only what the volume length covers. I/O failures surface as
/// [`CoreError::Io`]; a short-but-unmatched file is [`ImageKind::Raw`]
/// or [`ImageKind::Unknown`], never an error.
pub fn detect(volume: &dyn Volume) -> Result<ImageKind> {
    let total = volume.total_bytes();
    if total == 0 {
        return Ok(ImageKind::Unknown);
    }
    let head = read_at(volume, total, 0, total.min(HEAD_LEN), "image header prefix")?;

    // Offset-0 magics in the documented probe order. The FFU arm covers
    // both file orders: image-first (`ImageFlash` at 0) and
    // security-first (a 32-byte `cbSize` plus `SignedImage ` at 4).
    if head.starts_with(&VHDX_MAGIC) {
        return Ok(ImageKind::Vhdx);
    }
    if ffu::is_image_first(&head) || ffu::is_security_first(&head) {
        return Ok(ImageKind::Ffu);
    }
    if head.starts_with(&QCOW2_MAGIC) {
        return Ok(ImageKind::Qcow2);
    }
    if head.starts_with(&WIM_MAGIC) {
        return Ok(ImageKind::Wim);
    }
    if head.starts_with(&XZ_MAGIC) {
        return Ok(ImageKind::Xz);
    }
    if head.starts_with(&ZSTD_MAGIC) {
        return Ok(ImageKind::Zstd);
    }
    if head.starts_with(&BZIP2_MAGIC) {
        return Ok(ImageKind::Bzip2);
    }
    if head.starts_with(&GZIP_MAGIC) {
        return Ok(ImageKind::Gzip);
    }
    if head.starts_with(&PE_MAGIC) {
        return Ok(ImageKind::Pe);
    }

    // VHD: footer at the very end. Probed before ISO: a fixed VHD
    // converted from an ISO payload carries both magics and the outer
    // container must win.
    if total >= VHD_FOOTER_LEN {
        let base = total - VHD_FOOTER_LEN;
        let tail = read_at(
            volume,
            total,
            base,
            VHD_MAGIC.len() as u64,
            "vhd footer magic",
        )?;
        if tail == VHD_MAGIC {
            return Ok(ImageKind::Vhd);
        }
    }

    // ISO9660: volume descriptor set sector 16 (`CD001` from 0x8001).
    if total >= ISO_MAGIC_OFFSET + ISO_MAGIC.len() as u64 {
        let sector = read_at(
            volume,
            total,
            ISO_MAGIC_OFFSET,
            ISO_MAGIC.len() as u64,
            "iso volume descriptor magic",
        )?;
        if sector == ISO_MAGIC {
            return Ok(ImageKind::Iso);
        }
    }

    if total >= SHORTEST_MAGIC {
        Ok(ImageKind::Raw)
    } else {
        Ok(ImageKind::Unknown)
    }
}

/// An opened, detected and header-validated image.
///
/// For the container families with a logical reader (VHD, VHDX, FFU
/// and qcow2) the volume is the container's *contents* and the size
/// its *virtual* size — a dynamic VHD's virtual size lives in its
/// footer, far below the file length. Every other kind is
/// detection-only: the volume is the file itself and the size its
/// length.
pub struct Image {
    kind: ImageKind,
    size_bytes: u64,
    volume: Box<dyn Volume>,
}

impl std::fmt::Debug for Image {
    /// The kind and the size: the reader itself has no useful textual
    /// shape (it is an open file), so it is not rendered.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Image")
            .field("kind", &self.kind)
            .field("size_bytes", &self.size_bytes)
            .finish_non_exhaustive()
    }
}

impl Image {
    /// The detected container family.
    #[must_use]
    pub fn kind(&self) -> ImageKind {
        self.kind.clone()
    }

    /// The virtual size in bytes for the container families with a
    /// logical reader (the VHD current size, the VHDX virtual disk
    /// size, the qcow2 virtual size, the FFU final-table extent) and
    /// the file length for every other kind.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// The logical contents: the container reader for VHD, VHDX, FFU
    /// and qcow2 (a fixed VHD presents file bytes `0..current_size`,
    /// without its footer), the file itself for every other kind. No
    /// bytes have been consumed: every probe and header reads
    /// positionally.
    #[must_use]
    pub fn volume(&self) -> &dyn Volume {
        &*self.volume
    }

    /// Consume the image into its reader.
    #[must_use]
    pub fn into_volume(self) -> Box<dyn Volume> {
        self.volume
    }
}

/// Open the regular file at `path` read-only, detect its container
/// kind, validate the container header and expose the logical
/// contents.
///
/// A file whose magic commits to VHD, VHDX, FFU or qcow2 but whose
/// header is truncated or self-contradictory fails here with the field
/// and the reason named — it never falls back to [`ImageKind::Raw`].
/// Directories, devices and missing paths fail with the path named.
pub fn open_image(path: &Path) -> Result<Image> {
    let volume = FileVolume::open(path)?;
    let total = volume.total_bytes();
    let kind = detect(&volume)?;
    let (size_bytes, volume): (u64, Box<dyn Volume>) = match kind {
        ImageKind::Vhd => {
            let reader = vhd::open(Box::new(volume), total)?;
            (reader.total_bytes(), Box::new(reader))
        }
        ImageKind::Vhdx => {
            let reader = vhdx::open(Box::new(volume), total)?;
            (reader.total_bytes(), Box::new(reader))
        }
        ImageKind::Ffu => {
            let reader = ffu::open(Box::new(volume), total)?;
            (reader.total_bytes(), Box::new(reader))
        }
        ImageKind::Qcow2 => {
            let reader = qcow2::open(Box::new(volume), total)?;
            (reader.total_bytes(), Box::new(reader))
        }
        ImageKind::Iso
        | ImageKind::Wim
        | ImageKind::Gzip
        | ImageKind::Xz
        | ImageKind::Bzip2
        | ImageKind::Zstd
        | ImageKind::Pe
        | ImageKind::Raw
        | ImageKind::Unknown => (total, Box::new(volume)),
    };
    Ok(Image {
        kind,
        size_bytes,
        volume,
    })
}

/// Read `len` bytes at absolute `offset` from `volume`: the window is
/// bounds-checked against `total` with checked arithmetic before any
/// I/O, and a window running past the volume end is refused naming
/// `what`, the offset, the length and the total — never zero-padded.
/// Shared by every validator in this module.
pub(crate) fn read_at(
    volume: &dyn Volume,
    total: u64,
    offset: u64,
    len: u64,
    what: &str,
) -> Result<Vec<u8>> {
    let end = offset.checked_add(len).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} of {len} bytes at offset {offset} overflows the byte offset arithmetic"
        ))
    })?;
    if end > total {
        return Err(CoreError::invalid(format!(
            "{what} of {len} bytes at offset {offset} (bytes {offset}..{end}) runs past \
             the {total} byte volume end"
        )));
    }
    let count = usize::try_from(len)
        .map_err(|_| CoreError::invalid(format!("{what} length {len} is not addressable")))?;
    let mut out = vec![0u8; count];
    volume.read_exact_at(offset, &mut out)?;
    Ok(out)
}

/// `len` bytes at `at` of `bytes`: refuses with `what` and the byte
/// range when the window is not there. No indexing, no panics.
pub(crate) fn window<'a>(bytes: &'a [u8], at: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = at.checked_add(len).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} byte range {at}.. overflows the offset arithmetic"
        ))
    })?;
    bytes.get(at..end).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} needs bytes {at}..{end} but carries only {} bytes",
            bytes.len()
        ))
    })
}

/// Big-endian `u32` at `at` of `bytes`: refuses with `what` and the
/// byte range when the window is not there. No indexing, no panics.
pub(crate) fn be_u32_at(bytes: &[u8], at: usize, what: &str) -> Result<u32> {
    window(bytes, at, 4, what).and_then(|four| {
        four.try_into().map(u32::from_be_bytes).map_err(|_| {
            CoreError::invalid(format!("{what} bytes {at}..{} do not form a u32", at + 4))
        })
    })
}

/// Big-endian `u64` at `at` of `bytes`, same contract as [`be_u32_at`].
pub(crate) fn be_u64_at(bytes: &[u8], at: usize, what: &str) -> Result<u64> {
    window(bytes, at, 8, what).and_then(|eight| {
        eight.try_into().map(u64::from_be_bytes).map_err(|_| {
            CoreError::invalid(format!("{what} bytes {at}..{} do not form a u64", at + 8))
        })
    })
}

/// Little-endian `u16` at `at` of `bytes`, same contract as
/// [`be_u32_at`].
pub(crate) fn le_u16_at(bytes: &[u8], at: usize, what: &str) -> Result<u16> {
    window(bytes, at, 2, what).and_then(|pair| {
        pair.try_into().map(u16::from_le_bytes).map_err(|_| {
            CoreError::invalid(format!("{what} bytes {at}..{} do not form a u16", at + 2))
        })
    })
}

/// Little-endian `u32` at `at` of `bytes`, same contract as
/// [`be_u32_at`].
pub(crate) fn le_u32_at(bytes: &[u8], at: usize, what: &str) -> Result<u32> {
    window(bytes, at, 4, what).and_then(|four| {
        four.try_into().map(u32::from_le_bytes).map_err(|_| {
            CoreError::invalid(format!("{what} bytes {at}..{} do not form a u32", at + 4))
        })
    })
}

/// Little-endian `u64` at `at` of `bytes`, same contract as
/// [`be_u32_at`].
pub(crate) fn le_u64_at(bytes: &[u8], at: usize, what: &str) -> Result<u64> {
    window(bytes, at, 8, what).and_then(|eight| {
        eight.try_into().map(u64::from_le_bytes).map_err(|_| {
            CoreError::invalid(format!("{what} bytes {at}..{} do not form a u64", at + 8))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;

    /// Detect `bytes` through a memory volume of exactly that length
    /// (`VecVolume` holds zero bytes fine, which is the empty-file
    /// shape `detect` reports as unknown).
    fn detect_bytes(bytes: &[u8]) -> ImageKind {
        let mut volume = VecVolume::new(bytes.len() as u64, 512).expect("the RAM for the fixture");
        if !bytes.is_empty() {
            volume.write_all_at(0, bytes).expect("the fixture fits");
        }
        detect(&volume).expect("detection never fails on a memory volume")
    }

    #[test]
    fn detect_commits_to_every_offset_zero_magic() {
        // (first bytes, expected kind); each file is padded past every
        // probe so only the leading magic decides.
        let mut cases: Vec<(Vec<u8>, ImageKind)> = vec![
            (b"vhdxfile".to_vec(), ImageKind::Vhdx),
            (b"ImageFlash".to_vec(), ImageKind::Ffu),
            (vec![0x51, 0x46, 0x49, 0xFB], ImageKind::Qcow2),
            (b"MSWIM\0\0\0".to_vec(), ImageKind::Wim),
            (vec![0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], ImageKind::Xz),
            (vec![0x28, 0xB5, 0x2F, 0xFD], ImageKind::Zstd),
            (b"BZh".to_vec(), ImageKind::Bzip2),
            (vec![0x1F, 0x8B], ImageKind::Gzip),
            (b"MZ".to_vec(), ImageKind::Pe),
        ];
        for (head, _) in cases.iter_mut() {
            head.resize(0x9000, 0);
        }
        for (head, want) in cases {
            assert_eq!(detect_bytes(&head), want);
        }
    }

    #[test]
    fn detect_sees_the_security_first_ffu_order() {
        // A security-first FFU shows `cbSize` 32 then `SignedImage ` at
        // bytes 4..16 (the layout real DISM files use).
        let mut head = vec![0u8; 0x9000];
        head[0..4].copy_from_slice(&32u32.to_le_bytes());
        head[4..16].copy_from_slice(b"SignedImage ");
        assert_eq!(detect_bytes(&head), ImageKind::Ffu);
    }

    #[test]
    fn detect_sees_iso_and_vhd_at_their_offsets() {
        let mut iso = vec![0u8; 0x9000];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(detect_bytes(&iso), ImageKind::Iso);

        let mut vhd = vec![0u8; 1024];
        vhd[512..520].copy_from_slice(b"conectix");
        assert_eq!(detect_bytes(&vhd), ImageKind::Vhd);
    }

    #[test]
    fn detect_prefers_vhd_over_an_iso_payload() {
        // A fixed VHD converted from an ISO (`qemu-img convert -O vpc`)
        // carries both signals: the ISO magic in its payload at 0x8001
        // and the footer at its end. The outer container must win, or
        // the plan would raw-copy the container.
        let mut both = vec![0u8; 0x9000];
        both[0x8001..0x8006].copy_from_slice(b"CD001");
        let base = both.len() - 512;
        both[base..base + 8].copy_from_slice(b"conectix");
        assert_eq!(detect_bytes(&both), ImageKind::Vhd);
    }

    #[test]
    fn detect_reports_raw_and_unknown_without_panicking() {
        assert_eq!(detect_bytes(&[]), ImageKind::Unknown);
        assert_eq!(detect_bytes(&[0xFF]), ImageKind::Unknown);
        assert_eq!(detect_bytes(&[0xAA; 2]), ImageKind::Raw);
        assert_eq!(detect_bytes(&[0xAA; 4096]), ImageKind::Raw);
        // `QFI` without the fourth magic byte is not qcow2.
        assert_eq!(detect_bytes(b"QFI"), ImageKind::Raw);
    }

    #[test]
    fn open_image_refuses_directories_and_missing_paths() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let error = open_image(dir.path()).unwrap_err();
        assert!(
            error.to_string().contains("not a regular file"),
            "{error:?}"
        );
        let error = open_image(&dir.path().join("absent.bin")).unwrap_err();
        assert!(error.to_string().contains("absent.bin"), "{error:?}");
    }

    #[test]
    fn open_image_passes_detection_through_for_plain_kinds() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("plain.bin");
        std::fs::write(&path, [0xAAu8; 4096]).expect("the fixture file");
        let image = open_image(&path).expect("a raw file opens");
        assert_eq!(image.kind(), ImageKind::Raw);
        assert_eq!(image.size_bytes(), 4096);
        assert_eq!(image.volume().total_bytes(), 4096);
        assert_eq!(image.into_volume().total_bytes(), 4096);

        let empty = dir.path().join("empty.bin");
        std::fs::write(&empty, []).expect("the empty file");
        let image = open_image(&empty).expect("an empty file opens");
        assert_eq!(image.kind(), ImageKind::Unknown);
        assert_eq!(image.size_bytes(), 0);
    }
}
