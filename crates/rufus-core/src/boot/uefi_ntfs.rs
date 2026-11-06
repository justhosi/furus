//! The UEFI:NTFS shim: the embedded 1 MiB image written verbatim at
//! the ESP partition's offset (`drive.c:2501-2515`, log `Writing
//! UEFI:NTFS data...`).
//!
//! The image is its own FAT12 filesystem (label `RUFUS_BOOT`) holding
//! the NTFS EFI driver (`uefi-ntfs.efi`): Rufus writes the embedded
//! resource whole at the first partition's offset, and we do the same
//! — the bytes land exactly as the manifest pins them (resource 502)
//! and are never formatted by us. The partition geometry (the offset
//! and the window the image must fit) comes from the planner
//! ([`esp_window`](crate::part::plan::esp_window), slice 8); this
//! module only bounds the write against the caller's limit and
//! performs it.
//!
//! [`install`] is the testable core over explicit bytes: one bound
//! check, one whole-image write, nothing else (no flush — the caller
//! owns it). [`install_embedded`] loads the pinned resource through
//! [`load`](super::load) and delegates. Like every installer here this
//! proves bytes on a volume, not bootability: no stick has been booted
//! on hardware.

use crate::boot::Resource;
use crate::boot::load;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;

/// Exact byte count of the UEFI:NTFS shim image (resource 502): 1 MiB,
/// the planner's default ESP window, so the pinned image fills it
/// exactly.
pub const IMAGE_BYTES: u64 = 1_048_576;

/// What [`install`] wrote: the image byte count and the offset it
/// landed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    bytes: u64,
    offset: u64,
}

impl Installed {
    /// Bytes of the image landed at [`offset`](Self::offset) (the
    /// whole image, always).
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Byte offset the image landed at (the ESP partition's start).
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

/// Write the `image` bytes whole at `offset`, refusing unless the full
/// image fits below `limit`.
///
/// The steps run in this order: an empty image refuses naming its
/// `0 bytes`; an `offset + len` that overflows `u64` refuses naming
/// both numbers; an end past `limit` refuses naming the offset, the
/// image length and the limit; only then does the whole image write at
/// `offset`. The bound check runs before any write, so a refusal
/// leaves the volume untouched. Nothing else is written and nothing is
/// flushed: the caller owns the flush, and the image is a complete
/// filesystem already, so there is no boot record to lay after it.
pub fn install(disk: &mut dyn Volume, image: &[u8], offset: u64, limit: u64) -> Result<Installed> {
    let len = u64::try_from(image.len())
        .map_err(|_| CoreError::invalid("a uefi-ntfs image longer than u64: refusing"))?;
    if len == 0 {
        return Err(CoreError::invalid(
            "uefi-ntfs image is empty (0 bytes): refusing".to_string(),
        ));
    }
    let end = offset.checked_add(len).ok_or_else(|| {
        CoreError::invalid(format!(
            "uefi-ntfs image end at offset {offset} plus {len} bytes overflows u64: refusing"
        ))
    })?;
    if end > limit {
        return Err(CoreError::invalid(format!(
            "uefi-ntfs image of {len} bytes at offset {offset} runs past the {limit} byte limit: refusing"
        )));
    }
    disk.write_all_at(offset, image)?;
    Ok(Installed { bytes: len, offset })
}

/// Write the embedded UEFI:NTFS image ([`Resource::UefiNtfsImage`])
/// whole at `offset`, refusing unless it fits below `limit`.
///
/// Loads through [`load`](super::load) — the pinned size and digest
/// are verified there — then delegates to [`install`], so the same
/// pre-write bound check guards the embedded bytes too.
pub fn install_embedded(disk: &mut dyn Volume, offset: u64, limit: u64) -> Result<Installed> {
    let payload = load(Resource::UefiNtfsImage)?;
    install(disk, payload.bytes(), offset, limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;

    /// A zeroed volume of `len` bytes with 512-byte sectors.
    fn blank(len: u64) -> VecVolume {
        VecVolume::new(len, 512).expect("the ram volume fits")
    }

    /// A recognisable patterned image of `len` bytes.
    fn patterned(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| ((index * 5 + 1) % 251) as u8)
            .collect()
    }

    /// Read `len` bytes at `offset` back out of `disk`.
    fn read_back(disk: &VecVolume, offset: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        disk.read_exact_at(offset, &mut out)
            .expect("the test read fits");
        out
    }

    #[test]
    fn image_lands_whole_at_the_offset_and_nowhere_else() {
        // A prefilled 4 MiB volume with a recognisable background: the
        // 1 MiB image lands at 1 MiB, and every byte outside it keeps
        // the background.
        const LEN: u64 = 4 * 1024 * 1024;
        const OFFSET: u64 = 1024 * 1024;
        let background: Vec<u8> = (0..LEN as usize)
            .map(|index| ((index * 11 + 7) % 251) as u8)
            .collect();
        let mut disk = blank(LEN);
        disk.write_all_at(0, &background)
            .expect("the prefill lands");
        let image = patterned(IMAGE_BYTES as usize);
        let installed = install(&mut disk, &image, OFFSET, LEN).expect("the install runs");
        assert_eq!(installed.bytes(), IMAGE_BYTES, "the whole image counts");
        assert_eq!(installed.offset(), OFFSET, "the offset reports");
        assert_eq!(
            read_back(&disk, OFFSET, image.len()),
            image,
            "the image reads back whole"
        );
        assert_eq!(
            read_back(&disk, 0, OFFSET as usize),
            background
                .get(..OFFSET as usize)
                .expect("the head window fits"),
            "not one byte before the offset moved"
        );
        let tail = OFFSET + IMAGE_BYTES;
        assert_eq!(
            read_back(&disk, tail, (LEN - tail) as usize),
            background
                .get(tail as usize..)
                .expect("the tail window fits"),
            "not one byte past the image moved"
        );
    }

    #[test]
    fn second_write_is_idempotent() {
        // Writing the same image twice leaves the same bytes: the
        // install is a plain overwrite with no chaining state.
        let mut disk = blank(2 * 1024 * 1024);
        let image = patterned(512);
        let first = install(&mut disk, &image, 1024, 2 * 1024 * 1024).expect("the first lands");
        let second = install(&mut disk, &image, 1024, 2 * 1024 * 1024).expect("the second lands");
        assert_eq!(first, second, "both reports agree");
        assert_eq!(
            read_back(&disk, 1024, image.len()),
            image,
            "the bytes are the image either way"
        );
    }

    #[test]
    fn empty_image_is_refused_naming_zero_bytes() {
        let mut disk = blank(1024 * 1024);
        let before = read_back(&disk, 0, 1024);
        let error = install(&mut disk, &[], 0, 1024 * 1024).expect_err("an empty image refuses");
        let text = error.to_string();
        assert!(text.contains("0 bytes"), "names the length: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            read_back(&disk, 0, 1024),
            before,
            "the refusal wrote nothing"
        );
    }

    #[test]
    fn oversized_image_is_refused_naming_all_three_numbers() {
        // A 100-byte image against a limit one byte short: the bound
        // check fires before any write, naming the offset, the length
        // and the limit, and the volume stays byte-identical.
        let mut disk = blank(4096);
        let before = read_back(&disk, 0, 4096);
        let image = patterned(100);
        let error = install(&mut disk, &image, 1000, 1099).expect_err("an overrun refuses");
        let text = error.to_string();
        assert!(text.contains("1000"), "names the offset: {text}");
        assert!(text.contains("100"), "names the length: {text}");
        assert!(text.contains("1099"), "names the limit: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            read_back(&disk, 0, 4096),
            before,
            "the pre-write check leaves the image untouched"
        );
    }

    #[test]
    fn overflowing_end_is_refused() {
        // `offset + len` past `u64::MAX` refuses on the arithmetic
        // itself, naming both numbers, before any bound comparison.
        let mut disk = blank(4096);
        let image = patterned(16);
        let error = install(&mut disk, &image, u64::MAX - 8, u64::MAX)
            .expect_err("an overflowing end refuses");
        let text = error.to_string();
        assert!(
            text.contains(&(u64::MAX - 8).to_string()),
            "names the offset: {text}"
        );
        assert!(text.contains("16"), "names the length: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }

    /// `assets/resources/` next to the workspace root, without going
    /// through asset-dir resolution: the pin below must not depend on
    /// the environment.
    fn resources_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/resources"
        ))
    }

    /// The one shared asset seeder lives in
    /// [`crate::pipeline::bootloader::end_to_end`]: this test calls it
    /// there, so parallel threads stage through unique temp names plus
    /// an atomic `rename` and never race on the final asset bytes.
    use crate::pipeline::bootloader::end_to_end::seed_exe_assets;

    #[test]
    fn image_bytes_matches_the_pinned_resource_size() {
        // `IMAGE_BYTES` duplicates the manifest size the [`Resource`]
        // pins: the equality below ties them, so a manifest
        // regeneration that changes the payload fails here until both
        // move in lockstep.
        assert_eq!(
            IMAGE_BYTES,
            Resource::UefiNtfsImage.size(),
            "the shim size and the resource size agree"
        );
    }

    #[test]
    fn embedded_install_returns_the_pinned_one_mib() {
        // The real resource through the real resolution: the report
        // carries exactly 1 MiB at the ESP offset, and the volume bytes
        // are the manifest bytes.
        seed_exe_assets();
        let mut disk = blank(2 * 1024 * 1024);
        let installed = install_embedded(&mut disk, 1024 * 1024, 2 * 1024 * 1024)
            .expect("the embedded install runs");
        assert_eq!(installed.bytes(), IMAGE_BYTES, "the pinned 1 MiB");
        assert_eq!(installed.offset(), 1024 * 1024, "the ESP offset");
        let want = std::fs::read(resources_dir().join(Resource::UefiNtfsImage.file()))
            .expect("the pinned asset reads");
        assert_eq!(
            read_back(&disk, 1024 * 1024, want.len()),
            want,
            "the embedded bytes land whole"
        );
    }
}
