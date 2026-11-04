//! The S19 bootloader payload foundation: verified loading of the six
//! embedded bootloader resources every later S19 slice builds on.
//!
//! The bytes live in `assets/resources/` and are pinned by
//! `assets/manifest.json`: each [`Resource`] carries its manifest id,
//! file name, exact size and SHA-256, and [`load_from`] refuses anything
//! that does not match all of them. [`load`] is the production entry
//! point (it resolves through [`asset_path`](crate::paths::asset_path));
//! [`load_from`] is the testable core over an explicit directory. The
//! Syslinux installer lives next to the family decision (see
//! [`syslinux::install_loader`]); the GRUB2 / GRUB4DOS installers land
//! in later slices.
//!
//! [`syslinux`] decides the embedded Syslinux family from a detected
//! version or the `ldlinux.c32` presence and locates the payload
//! directory over a tree source; it writes nothing and patches no
//! sectors, which later S19 slices own.

pub mod syslinux;

use std::path::Path;

use crate::error::CoreError;
use crate::error::Result;
use crate::hash::Algo;
use crate::hash::hash_reader;
use crate::paths::asset_path;

/// One embedded bootloader payload, pinned against `assets/manifest.json`.
///
/// The numeric ids are the manifest resource ids (400-403 Syslinux,
/// 450-451 Grub4DOS); the sizes and digests are the manifest `bytes` and
/// `sha256` values, so any manifest regeneration must update this enum
/// in lockstep (the load test below guards the drift).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    /// Syslinux 4.07 VBR (`ldlinux.bss`), manifest id 400.
    Syslinux407Vbr,
    /// Syslinux 4.07 core (`ldlinux.sys`), manifest id 401.
    Syslinux407Core,
    /// Syslinux 6.04 VBR (`ldlinux.bss`), manifest id 402.
    Syslinux604Vbr,
    /// Syslinux 6.04 core (`ldlinux.sys`), manifest id 403.
    Syslinux604Core,
    /// Grub4DOS MBR (`grldr.mbr`), manifest id 450.
    Grub4DosMbr,
    /// Grub4DOS core (`grldr`), manifest id 451.
    Grub4DosCore,
}

impl Resource {
    /// Every variant, so the tests below load each payload and no new
    /// variant can skip that coverage silently (a new variant must be
    /// added here to keep the file-name test exhaustive).
    pub const ALL: [Resource; 6] = [
        Resource::Syslinux407Vbr,
        Resource::Syslinux407Core,
        Resource::Syslinux604Vbr,
        Resource::Syslinux604Core,
        Resource::Grub4DosMbr,
        Resource::Grub4DosCore,
    ];

    /// Manifest resource id.
    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            Self::Syslinux407Vbr => 400,
            Self::Syslinux407Core => 401,
            Self::Syslinux604Vbr => 402,
            Self::Syslinux604Core => 403,
            Self::Grub4DosMbr => 450,
            Self::Grub4DosCore => 451,
        }
    }

    /// Bare file name under `assets/resources/`.
    #[must_use]
    pub fn file(self) -> &'static str {
        match self {
            Self::Syslinux407Vbr => "RCDATA_400.bin",
            Self::Syslinux407Core => "RCDATA_401.bin",
            Self::Syslinux604Vbr => "RCDATA_402.bin",
            Self::Syslinux604Core => "RCDATA_403.bin",
            Self::Grub4DosMbr => "RCDATA_450.bin",
            Self::Grub4DosCore => "RCDATA_451.bin",
        }
    }

    /// Exact manifest byte count; anything else refuses as corrupt.
    #[must_use]
    pub fn size(self) -> u64 {
        match self {
            Self::Syslinux407Vbr => 512,
            Self::Syslinux407Core => 36488,
            Self::Syslinux604Vbr => 512,
            Self::Syslinux604Core => 68121,
            Self::Grub4DosMbr => 8192,
            Self::Grub4DosCore => 42742,
        }
    }

    /// Pinned manifest SHA-256, lowercase hex.
    #[must_use]
    pub fn sha256(self) -> &'static str {
        match self {
            Self::Syslinux407Vbr => {
                "8dc6ec58b4f1df391db68d9e2165ccd47d84f4ba64675f87b677077aae5b53fa"
            }
            Self::Syslinux407Core => {
                "d5b6310740a596ba4367719a3dff4b3442f6da81cbeafbb0bf3fab026d8bc910"
            }
            Self::Syslinux604Vbr => {
                "cc40ba0349782cb4c9021e54dcc0a4540c3a8b96088b3a5648671926ef44d2f0"
            }
            Self::Syslinux604Core => {
                "73b62767a16200b9af193a7d5c94e9c294c6dbb6d5b17c15038c9f3173c9a7bc"
            }
            Self::Grub4DosMbr => "a2a8769371eb57c5e79b3cea4a911275af4743f10f420ed6d26e4eec5c865059",
            Self::Grub4DosCore => {
                "9a2c946704017fa8dc4e03a8a58d754d2d1607c2d2cd74f0e2920133f1192809"
            }
        }
    }

    /// Human-readable name for log and error messages.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Syslinux407Vbr => "Syslinux 4.07 VBR",
            Self::Syslinux407Core => "Syslinux 4.07 core",
            Self::Syslinux604Vbr => "Syslinux 6.04 VBR",
            Self::Syslinux604Core => "Syslinux 6.04 core",
            Self::Grub4DosMbr => "Grub4DOS MBR",
            Self::Grub4DosCore => "Grub4DOS core",
        }
    }
}

/// A verified payload: its [`Resource`] plus the exact bytes from disk.
///
/// The bytes are checked at load time (see [`load_from`]), so holding a
/// `Payload` means the size and digest already matched the pinned values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    resource: Resource,
    bytes: Vec<u8>,
}

impl Payload {
    /// The loaded bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Byte count (always equals [`Resource::size`] of [`resource`](Self::resource)).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the payload holds no bytes (never true for the six pinned
    /// resources — every size is non-zero — but the [`len`](Self::len)
    /// companion keeps the API unsurprising).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Which resource these bytes were verified against.
    #[must_use]
    pub fn resource(&self) -> Resource {
        self.resource
    }
}

/// Load `resource` from the resolved asset directory.
///
/// Resolves through [`asset_path`](crate::paths::asset_path), then
/// delegates to [`load_from`] so the file-name join lives in one place.
pub fn load(resource: Resource) -> Result<Payload> {
    let path = asset_path(resource.file())?;
    // `asset_path` hands back the file itself; its parent is the
    // directory `load_from` joins against. The parent always exists in
    // practice (resolution joins a file onto a directory), but there is
    // no `unwrap` on that assumption — a bare name refuses by name.
    let dir = path.parent().ok_or_else(|| {
        CoreError::invalid(format!(
            "asset {} ({}) resolved to a path with no parent directory",
            resource.label(),
            resource.file()
        ))
    })?;
    load_from(dir, resource)
}

/// Load `resource` from `dir`, verifying exact size and SHA-256 against
/// the pinned values.
///
/// A missing or unreadable file surfaces as [`CoreError::Io`] (the path
/// names the file); a size or digest mismatch is
/// [`CoreError::InvalidInput`] naming the resource label, the file name,
/// and both the expected and actual numbers/digests, so a log line is
/// enough to tell corruption from mis-packaging.
pub fn load_from(dir: &Path, resource: Resource) -> Result<Payload> {
    let path = dir.join(resource.file());
    let bytes = std::fs::read(&path).map_err(|source| CoreError::io(&path, source))?;
    let actual_len = bytes.len() as u64;
    if actual_len != resource.size() {
        return Err(CoreError::invalid(format!(
            "payload {} ({}) has size {actual_len} bytes, expected {} bytes",
            resource.label(),
            resource.file(),
            resource.size()
        )));
    }
    // Hash the bytes just read rather than re-reading the file: one
    // read, one failure mode, no window for the file to change between
    // the size check and the digest.
    let actual_sha = hash_reader(Algo::Sha256, &bytes as &[u8])?;
    if actual_sha != resource.sha256() {
        return Err(CoreError::invalid(format!(
            "payload {} ({}) has SHA-256 {actual_sha}, expected {}",
            resource.label(),
            resource.file(),
            resource.sha256()
        )));
    }
    Ok(Payload { resource, bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `assets/resources/` next to the workspace root, without going
    /// through asset-dir resolution (resolution depends on the
    /// environment; the anti-drift guard must not).
    fn resources_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/resources"
        ))
    }

    #[test]
    fn every_resource_loads_with_pinned_size_and_digest() {
        // The anti-drift guard: the file names, sizes and digests above
        // come from `assets/manifest.json`, so a manifest regeneration
        // that changes any of the six payloads fails here until the
        // enum is updated in lockstep.
        for resource in Resource::ALL {
            let payload = load_from(&resources_dir(), resource).expect("the pinned payload loads");
            assert_eq!(
                payload.len() as u64,
                resource.size(),
                "loaded length of {} matches the pinned size",
                resource.file()
            );
            assert_eq!(
                payload.resource(),
                resource,
                "the payload remembers its resource"
            );
            let actual = hash_reader(Algo::Sha256, payload.bytes()).expect("in-memory bytes hash");
            assert_eq!(
                actual,
                resource.sha256(),
                "SHA-256 of {} matches the pinned digest",
                resource.file()
            );
        }
    }

    #[test]
    fn missing_file_is_an_error_naming_the_resource() {
        // An empty directory: every load fails, and each error names its
        // file so the log says which payload is absent.
        let scratch = tempfile::tempdir().expect("scratch fits");
        for resource in Resource::ALL {
            let error = load_from(scratch.path(), resource).expect_err("a missing payload refuses");
            let text = error.to_string();
            assert!(
                text.contains(resource.file()),
                "the error names the file: {text}"
            );
        }
    }

    #[test]
    fn file_names_are_exactly_the_six_pinned_names() {
        // One assertion over every variant, so a future variant that is
        // added to `ALL` without a real payload file cannot slip past
        // the load test above (it would fail there on a missing file).
        let files: Vec<&str> = Resource::ALL.iter().map(|r| r.file()).collect();
        assert_eq!(
            files,
            [
                "RCDATA_400.bin",
                "RCDATA_401.bin",
                "RCDATA_402.bin",
                "RCDATA_403.bin",
                "RCDATA_450.bin",
                "RCDATA_451.bin",
            ],
            "the six pinned file names"
        );
    }

    #[test]
    fn resource_ids_are_the_six_manifest_ids() {
        // Sibling to the file-name guard: the numeric ids ride the same
        // manifest entries, so they pin in lockstep too.
        let ids: Vec<u16> = Resource::ALL.iter().map(|r| r.id()).collect();
        assert_eq!(
            ids,
            [400, 401, 402, 403, 450, 451],
            "the six manifest resource ids"
        );
    }

    #[test]
    fn truncated_file_is_an_error_naming_both_byte_counts() {
        // Copy a real payload and truncate it: the size check fires
        // before the digest, naming the file and both counts.
        let resource = Resource::Syslinux407Vbr;
        let bytes =
            std::fs::read(resources_dir().join(resource.file())).expect("the pinned file reads");
        let scratch = tempfile::tempdir().expect("scratch fits");
        let kept = bytes.len().saturating_sub(12);
        std::fs::write(scratch.path().join(resource.file()), &bytes[..kept])
            .expect("the truncated copy writes");
        let error = load_from(scratch.path(), resource).expect_err("a truncated payload refuses");
        let text = error.to_string();
        assert!(
            text.contains(resource.file()),
            "the error names the file: {text}"
        );
        assert!(
            text.contains(&kept.to_string()),
            "the error names the actual count: {text}"
        );
        assert!(
            text.contains(&resource.size().to_string()),
            "the error names the expected count: {text}"
        );
    }

    #[test]
    fn flipped_byte_is_an_error_naming_both_digests() {
        // Copy a real payload with one byte flipped at the same size:
        // the digest check fires, naming the file and both digests.
        let resource = Resource::Syslinux407Vbr;
        let mut bytes =
            std::fs::read(resources_dir().join(resource.file())).expect("the pinned file reads");
        bytes[0] ^= 0x01;
        let scratch = tempfile::tempdir().expect("scratch fits");
        std::fs::write(scratch.path().join(resource.file()), &bytes)
            .expect("the flipped copy writes");
        let error = load_from(scratch.path(), resource).expect_err("a flipped payload refuses");
        let text = error.to_string();
        assert!(
            text.contains(resource.file()),
            "the error names the file: {text}"
        );
        let actual = hash_reader(Algo::Sha256, &bytes as &[u8]).expect("the flipped bytes hash");
        assert_ne!(actual, resource.sha256(), "the flip changes the digest");
        assert!(
            text.contains(&actual),
            "the error names the actual digest: {text}"
        );
        assert!(
            text.contains(resource.sha256()),
            "the error names the expected digest: {text}"
        );
    }
}
