//! FreeDOS payloads: the 27 embedded files `ExtractFreeDOS` copies onto
//! the stick (`src/dos.c:344-403`, resource ids `src/resource.h:34-60`).
//!
//! The set is the FreeDOS kernel (`KERNEL.SYS`), its shell
//! (`COMMAND.COM`), the `DISPLAY.EXE` / `KEYB.EXE` / `MODE.COM`
//! utilities, the four keyboard-layout libraries (`KEYBOARD.SYS`,
//! `KEYBRD2.SYS` .. `KEYBRD4.SYS`) and the 18 EGA codepage files
//! (`EGA.CPX`, `EGA2.CPX` .. `EGA18.CPX`). The reference carries them as
//! `RCDATA` resources 300-326 and reuses those bytes verbatim — it
//! downloads nothing, and neither does this module: [`FreeDosFile::load`]
//! resolves through [`asset_path`](crate::paths::asset_path) and
//! [`FreeDosFile::load_from`] reads from an explicit directory, and both
//! verify the exact size then the SHA-256 through the shared
//! `verify_payload` check.
//!
//! The sizes and digests below are copied verbatim from
//! `assets/manifest.json` (the manifest is the source of truth — nothing
//! here was computed and pasted); the load test below reloads every file
//! and fails on any drift, so a manifest regeneration must update this
//! enum in lockstep.
//!
//! Install semantics, for the slice that consumes this table
//! (`ExtractFreeDOS`, `src/dos.c:344-403`): the reference creates
//! `LOCALE\` on the target, writes the first two resources
//! (`COMMAND.COM`, `KERNEL.SYS`) to the target root with hidden+system
//! attributes and the other 25 into `LOCALE\` with normal attributes
//! (`(i<2) ? path : locale_path`, `src/dos.c:344-381`), then finishes
//! with `SetDOSLocale(path, TRUE)` (`src/dos.c:403`). Declared gap: our
//! [`Fat32`](crate::fs::fat32::Fat32) `create_file` carries no attribute
//! parameter (every entry takes the plain archive attribute), so the
//! hidden+system marks cannot be reproduced through that API yet.
//!
//! Two naming notes, both verified against the `v4.15` tag. First, id 320
//! really is `EGA12.CPX` with the extension: that is the spelling in the
//! `res_name[]` table (`src/dos.c:346-351`) and the file on disk is
//! `res/freedos/EGA12.CPX`. The extensionless `ega12` that the FreeDOS
//! EGA picker returns (`dos_locale.rs`, codepages 30003/30029/30030/58335)
//! is a different string — the `mode con codepage prepare` argument the
//! reference writes into `AUTOEXEC.BAT` — not the extracted file name.
//! Second, the manifest's `UPX-packed ... utility` label on ids 309-326
//! is half right: the UPX part checks out — those files really are
//! UPX-compressed self-extracting DOS COM programs (libmagic reports
//! e.g. `FREE-DOS executable (COM), UPX compressed DOS code page font,
//! uncompressed 58880 bytes`) — but the name is wrong, they are EGA
//! codepage fonts, not utilities. Id 304 is likewise a UPX COM
//! (`MODE.COM`, 16244 bytes, `u_len` 30736; libmagic `UPX compressed,
//! uncompressed 30736 bytes`) yet the manifest calls it `FreeDOS boot
//! sector / loader stub`, which is also wrong — and that is exactly why
//! the boot record is not in this set (see below). The `UPX!` bytes are
//! a real UPX header, not a stray string: the stub, the UPX header and
//! `c_len` together account for the file length — `EGA.CPX` 6464 = 36-byte
//! stub + header + `c_len` 6312 (residual 152), id 320 8119 = 36 + header +
//! 7967 (152), `MODE.COM` 16244 = 34 + header + 16094 (150); `EGA18.CPX`
//! differs (35-byte stub: 5158 = 35 + header + 5030, residual 128), so no
//! single residual covers every file. That they are byte-identical to
//! upstream proves nothing against packing, because upstream ships them
//! packed. There is still no unpack step here or upstream: Rufus copies
//! the packed bytes verbatim and FreeDOS's own tools decompress them on
//! the target.
//!
//! What this module is not: it only loads and verifies — the install
//! flow and the `SetDOSLocale(path, TRUE)` call belong to a later slice.
//! And the FreeDOS boot record is not among these resources (boot-record
//! handling comes from ms-sys, per `license.h`), so a stick from this
//! slice alone will not boot.
//!
//! All error and assertion text is ASCII.

use std::path::Path;

use crate::error::CoreError;
use crate::error::Result;
use crate::paths::asset_path;

/// Where `ExtractFreeDOS` writes a payload (`src/dos.c:344-403`): the
/// first two resources go to the target root, the other 25 into `LOCALE\`
/// (`(i<2) ? path : locale_path`, `src/dos.c:377`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Destination {
    /// The target root: `COMMAND.COM` and `KERNEL.SYS` only.
    Root,
    /// The `LOCALE\` subdirectory: the other 25 payloads.
    Locale,
}

/// One embedded FreeDOS payload, pinned against `assets/manifest.json`.
///
/// The numeric ids are the manifest resource ids, which are the upstream
/// `RCDATA` ids (`IDR_FD_*`, `src/resource.h:34-60`); the sizes and
/// digests are the manifest `bytes` and `sha256` values, so any manifest
/// regeneration must update this enum in lockstep (the load test below
/// guards the drift).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FreeDosFile {
    /// `COMMAND.COM`, manifest id 300.
    CommandCom,
    /// `KERNEL.SYS`, manifest id 301.
    KernelSys,
    /// `DISPLAY.EXE`, manifest id 302.
    DisplayExe,
    /// `KEYB.EXE`, manifest id 303.
    KeybExe,
    /// `MODE.COM`, manifest id 304.
    ModeCom,
    /// `KEYBOARD.SYS`, manifest id 305.
    KeyboardSys,
    /// `KEYBRD2.SYS`, manifest id 306.
    Keybrd2Sys,
    /// `KEYBRD3.SYS`, manifest id 307.
    Keybrd3Sys,
    /// `KEYBRD4.SYS`, manifest id 308.
    Keybrd4Sys,
    /// `EGA.CPX`, manifest id 309.
    Ega,
    /// `EGA2.CPX`, manifest id 310.
    Ega2,
    /// `EGA3.CPX`, manifest id 311.
    Ega3,
    /// `EGA4.CPX`, manifest id 312.
    Ega4,
    /// `EGA5.CPX`, manifest id 313.
    Ega5,
    /// `EGA6.CPX`, manifest id 314.
    Ega6,
    /// `EGA7.CPX`, manifest id 315.
    Ega7,
    /// `EGA8.CPX`, manifest id 316.
    Ega8,
    /// `EGA9.CPX`, manifest id 317.
    Ega9,
    /// `EGA10.CPX`, manifest id 318.
    Ega10,
    /// `EGA11.CPX`, manifest id 319.
    Ega11,
    /// `EGA12.CPX`, manifest id 320.
    Ega12,
    /// `EGA13.CPX`, manifest id 321.
    Ega13,
    /// `EGA14.CPX`, manifest id 322.
    Ega14,
    /// `EGA15.CPX`, manifest id 323.
    Ega15,
    /// `EGA16.CPX`, manifest id 324.
    Ega16,
    /// `EGA17.CPX`, manifest id 325.
    Ega17,
    /// `EGA18.CPX`, manifest id 326.
    Ega18,
}

impl FreeDosFile {
    /// Every variant in id order, because `ExtractFreeDOS` iterates the
    /// `res_name[]` table in that order (`src/dos.c:374-401`) — and so no
    /// new variant can skip the load coverage silently (a new variant must
    /// be added here to keep the file-name test exhaustive).
    pub const ALL: [FreeDosFile; 27] = [
        FreeDosFile::CommandCom,
        FreeDosFile::KernelSys,
        FreeDosFile::DisplayExe,
        FreeDosFile::KeybExe,
        FreeDosFile::ModeCom,
        FreeDosFile::KeyboardSys,
        FreeDosFile::Keybrd2Sys,
        FreeDosFile::Keybrd3Sys,
        FreeDosFile::Keybrd4Sys,
        FreeDosFile::Ega,
        FreeDosFile::Ega2,
        FreeDosFile::Ega3,
        FreeDosFile::Ega4,
        FreeDosFile::Ega5,
        FreeDosFile::Ega6,
        FreeDosFile::Ega7,
        FreeDosFile::Ega8,
        FreeDosFile::Ega9,
        FreeDosFile::Ega10,
        FreeDosFile::Ega11,
        FreeDosFile::Ega12,
        FreeDosFile::Ega13,
        FreeDosFile::Ega14,
        FreeDosFile::Ega15,
        FreeDosFile::Ega16,
        FreeDosFile::Ega17,
        FreeDosFile::Ega18,
    ];

    /// Manifest resource id (300-326, the upstream `RCDATA` ids).
    #[must_use]
    pub fn id(self) -> u32 {
        match self {
            Self::CommandCom => 300,
            Self::KernelSys => 301,
            Self::DisplayExe => 302,
            Self::KeybExe => 303,
            Self::ModeCom => 304,
            Self::KeyboardSys => 305,
            Self::Keybrd2Sys => 306,
            Self::Keybrd3Sys => 307,
            Self::Keybrd4Sys => 308,
            Self::Ega => 309,
            Self::Ega2 => 310,
            Self::Ega3 => 311,
            Self::Ega4 => 312,
            Self::Ega5 => 313,
            Self::Ega6 => 314,
            Self::Ega7 => 315,
            Self::Ega8 => 316,
            Self::Ega9 => 317,
            Self::Ega10 => 318,
            Self::Ega11 => 319,
            Self::Ega12 => 320,
            Self::Ega13 => 321,
            Self::Ega14 => 322,
            Self::Ega15 => 323,
            Self::Ega16 => 324,
            Self::Ega17 => 325,
            Self::Ega18 => 326,
        }
    }

    /// Bare file name under `assets/resources/`.
    #[must_use]
    pub fn asset_file(self) -> &'static str {
        match self {
            Self::CommandCom => "RCDATA_300.bin",
            Self::KernelSys => "RCDATA_301.bin",
            Self::DisplayExe => "RCDATA_302.bin",
            Self::KeybExe => "RCDATA_303.bin",
            Self::ModeCom => "RCDATA_304.bin",
            Self::KeyboardSys => "RCDATA_305.bin",
            Self::Keybrd2Sys => "RCDATA_306.bin",
            Self::Keybrd3Sys => "RCDATA_307.bin",
            Self::Keybrd4Sys => "RCDATA_308.bin",
            Self::Ega => "RCDATA_309.bin",
            Self::Ega2 => "RCDATA_310.bin",
            Self::Ega3 => "RCDATA_311.bin",
            Self::Ega4 => "RCDATA_312.bin",
            Self::Ega5 => "RCDATA_313.bin",
            Self::Ega6 => "RCDATA_314.bin",
            Self::Ega7 => "RCDATA_315.bin",
            Self::Ega8 => "RCDATA_316.bin",
            Self::Ega9 => "RCDATA_317.bin",
            Self::Ega10 => "RCDATA_318.bin",
            Self::Ega11 => "RCDATA_319.bin",
            Self::Ega12 => "RCDATA_320.bin",
            Self::Ega13 => "RCDATA_321.bin",
            Self::Ega14 => "RCDATA_322.bin",
            Self::Ega15 => "RCDATA_323.bin",
            Self::Ega16 => "RCDATA_324.bin",
            Self::Ega17 => "RCDATA_325.bin",
            Self::Ega18 => "RCDATA_326.bin",
        }
    }

    /// Upstream file name: the `res_name[]` entry `ExtractFreeDOS` writes
    /// (`src/dos.c:346-351`).
    ///
    /// Id 320 is `EGA12.CPX` with the extension — that is the spelling in
    /// `res_name[]` and on disk (`res/freedos/EGA12.CPX`); the
    /// extensionless `ega12` from the EGA picker is the `mode` command
    /// argument, not the extracted file name (see the module docs).
    #[must_use]
    pub fn target_name(self) -> &'static str {
        match self {
            Self::CommandCom => "COMMAND.COM",
            Self::KernelSys => "KERNEL.SYS",
            Self::DisplayExe => "DISPLAY.EXE",
            Self::KeybExe => "KEYB.EXE",
            Self::ModeCom => "MODE.COM",
            Self::KeyboardSys => "KEYBOARD.SYS",
            Self::Keybrd2Sys => "KEYBRD2.SYS",
            Self::Keybrd3Sys => "KEYBRD3.SYS",
            Self::Keybrd4Sys => "KEYBRD4.SYS",
            Self::Ega => "EGA.CPX",
            Self::Ega2 => "EGA2.CPX",
            Self::Ega3 => "EGA3.CPX",
            Self::Ega4 => "EGA4.CPX",
            Self::Ega5 => "EGA5.CPX",
            Self::Ega6 => "EGA6.CPX",
            Self::Ega7 => "EGA7.CPX",
            Self::Ega8 => "EGA8.CPX",
            Self::Ega9 => "EGA9.CPX",
            Self::Ega10 => "EGA10.CPX",
            Self::Ega11 => "EGA11.CPX",
            Self::Ega12 => "EGA12.CPX",
            Self::Ega13 => "EGA13.CPX",
            Self::Ega14 => "EGA14.CPX",
            Self::Ega15 => "EGA15.CPX",
            Self::Ega16 => "EGA16.CPX",
            Self::Ega17 => "EGA17.CPX",
            Self::Ega18 => "EGA18.CPX",
        }
    }

    /// Exact manifest byte count; anything else refuses as corrupt.
    #[must_use]
    pub fn size(self) -> u64 {
        match self {
            Self::CommandCom => 87_772,
            Self::KernelSys => 46_256,
            Self::DisplayExe => 3_657,
            Self::KeybExe => 11_819,
            Self::ModeCom => 16_244,
            Self::KeyboardSys => 40_362,
            Self::Keybrd2Sys => 29_750,
            Self::Keybrd3Sys => 32_178,
            Self::Keybrd4Sys => 13_105,
            Self::Ega => 6_464,
            Self::Ega2 => 7_059,
            Self::Ega3 => 5_469,
            Self::Ega4 => 4_431,
            Self::Ega5 => 7_217,
            Self::Ega6 => 7_409,
            Self::Ega7 => 5_387,
            Self::Ega8 => 6_973,
            Self::Ega9 => 5_785,
            Self::Ega10 => 5_543,
            Self::Ega11 => 7_228,
            Self::Ega12 => 8_119,
            Self::Ega13 => 6_281,
            Self::Ega14 => 7_758,
            Self::Ega15 => 6_458,
            Self::Ega16 => 7_793,
            Self::Ega17 => 8_929,
            Self::Ega18 => 5_158,
        }
    }

    /// Pinned manifest SHA-256, lowercase hex.
    #[must_use]
    pub fn sha256(self) -> &'static str {
        match self {
            Self::CommandCom => "077808379e896476f7f69d62e6c8989d8fc23e8ef58d1c8492db1ac106784107",
            Self::KernelSys => "57504a0d5e1d57a0407d995e77fcebb9627da2c0dbe0f1cbf7c5fa901d2efc6c",
            Self::DisplayExe => "16c7ab70957f72974d644f1d2dcbde3f1921d2f49cee2a03ca5173fc7e6ddbae",
            Self::KeybExe => "1845b9a91b933042d85d8c9b129e1d61aa014b90d1371ad4fc9724aa97d391d8",
            Self::ModeCom => "a8dfbfd17b7402407cfe35b9fdb5a72e6894d488f6c736289eb0991be4a1ab09",
            Self::KeyboardSys => "5cf40be4b062681f4b50446a60f0bd4b5077451ef278dea74044ef22862fb433",
            Self::Keybrd2Sys => "39131eddb9c55a4488fa4b3555f5c0f4d00acaf197b91adb5b5c79123f844a56",
            Self::Keybrd3Sys => "00b0e774792fde542eb3d29e9b1de1e11d00bf685e39989d91b6b45a5453a401",
            Self::Keybrd4Sys => "3d4723d1c5c2e276849f8353790f0ced5b2eb4ff5464c2be58bee5d07a7878e8",
            Self::Ega => "8c903b7a9e35715d38ee29a3ed42be3975c0840dbfd4fc5f9f028632bf28758d",
            Self::Ega2 => "60a4b001c05eb5c21ec4463fe5a31d890a566cd9ef3309d61b56f671f1c454fc",
            Self::Ega3 => "84ba78e35a0b3b2a55c829c26a25aca27ff1bdd07e3f918d0a93e6f5bb218a4a",
            Self::Ega4 => "3bb7958d837e00639c5d97943bcc9073b579eba2e9f2730a2d65ffc4da34be30",
            Self::Ega5 => "15726b1ee4b2deb48f4b93f5e209b486db7cbe8cf0223692466b7aa1dd3b8743",
            Self::Ega6 => "4791297678611ab4900f137853002233a12e2c0387f9db5259df33e0213ff0ff",
            Self::Ega7 => "fe5b927dccd2c5c8f792d827b871248b06ff79b20d9d1807eced5b89122dcc04",
            Self::Ega8 => "30a37619137f93fff9b8ab35e7cb7ab573bf411e575046ae468e0c884df4c936",
            Self::Ega9 => "cb7615db6ae6b9bf2e12d9bea079126478ea1b0ff48e4bd378c538d7a077f987",
            Self::Ega10 => "847c835ef80284704ef3594032cfffde4d22958eb8bc154c5a282ee3c07e920a",
            Self::Ega11 => "1793d99f8cd9d6017e6a0dd14a679080ba60e46fb9b59c344b5df986c50973ee",
            Self::Ega12 => "02751b3aa18225c197e9b0fdadbbd5989b6e76b13aec19c350956f64c3b2910a",
            Self::Ega13 => "287073ea7ad566d57b3c82ad84e079a7268a699dca863c2132f9c3faa02ac02e",
            Self::Ega14 => "76a8f3737a198961750783f74cb3b5f5054aa8491a36f33ba5c410528e97de22",
            Self::Ega15 => "26a2395cd6651a715ce78f4e70ae4d2b959e32aca775241a3bb094ae7efe9fee",
            Self::Ega16 => "e8ad25e433e3213609d44d25e690aee046192f4f91b3ee705ac28a0643b4da74",
            Self::Ega17 => "a53f84a041014a3815f489b71336a0a1253f853c6fc10d1c7c60020d9453c717",
            Self::Ega18 => "11944b119a838656de3fc795521e90bbc610b000fe603f95f8c685ee21216b1f",
        }
    }

    /// Human-readable name for log and error messages.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::CommandCom => "FreeDOS COMMAND.COM",
            Self::KernelSys => "FreeDOS KERNEL.SYS",
            Self::DisplayExe => "FreeDOS DISPLAY.EXE",
            Self::KeybExe => "FreeDOS KEYB.EXE",
            Self::ModeCom => "FreeDOS MODE.COM",
            Self::KeyboardSys => "FreeDOS KEYBOARD.SYS",
            Self::Keybrd2Sys => "FreeDOS KEYBRD2.SYS",
            Self::Keybrd3Sys => "FreeDOS KEYBRD3.SYS",
            Self::Keybrd4Sys => "FreeDOS KEYBRD4.SYS",
            Self::Ega => "FreeDOS EGA.CPX",
            Self::Ega2 => "FreeDOS EGA2.CPX",
            Self::Ega3 => "FreeDOS EGA3.CPX",
            Self::Ega4 => "FreeDOS EGA4.CPX",
            Self::Ega5 => "FreeDOS EGA5.CPX",
            Self::Ega6 => "FreeDOS EGA6.CPX",
            Self::Ega7 => "FreeDOS EGA7.CPX",
            Self::Ega8 => "FreeDOS EGA8.CPX",
            Self::Ega9 => "FreeDOS EGA9.CPX",
            Self::Ega10 => "FreeDOS EGA10.CPX",
            Self::Ega11 => "FreeDOS EGA11.CPX",
            Self::Ega12 => "FreeDOS EGA12.CPX",
            Self::Ega13 => "FreeDOS EGA13.CPX",
            Self::Ega14 => "FreeDOS EGA14.CPX",
            Self::Ega15 => "FreeDOS EGA15.CPX",
            Self::Ega16 => "FreeDOS EGA16.CPX",
            Self::Ega17 => "FreeDOS EGA17.CPX",
            Self::Ega18 => "FreeDOS EGA18.CPX",
        }
    }

    /// Where `ExtractFreeDOS` writes this payload: the target root for
    /// the first two resources, `LOCALE\` for the other 25
    /// (`(i<2) ? path : locale_path`, `src/dos.c:377`).
    #[must_use]
    pub fn destination(self) -> Destination {
        match self {
            Self::CommandCom | Self::KernelSys => Destination::Root,
            Self::DisplayExe
            | Self::KeybExe
            | Self::ModeCom
            | Self::KeyboardSys
            | Self::Keybrd2Sys
            | Self::Keybrd3Sys
            | Self::Keybrd4Sys
            | Self::Ega
            | Self::Ega2
            | Self::Ega3
            | Self::Ega4
            | Self::Ega5
            | Self::Ega6
            | Self::Ega7
            | Self::Ega8
            | Self::Ega9
            | Self::Ega10
            | Self::Ega11
            | Self::Ega12
            | Self::Ega13
            | Self::Ega14
            | Self::Ega15
            | Self::Ega16
            | Self::Ega17
            | Self::Ega18 => Destination::Locale,
        }
    }

    /// Load this payload from the resolved asset directory.
    ///
    /// Resolves through [`asset_path`](crate::paths::asset_path), then
    /// delegates to [`load_from`](Self::load_from) so the file-name join
    /// lives in one place.
    pub fn load(self) -> Result<Vec<u8>> {
        let path = asset_path(self.asset_file())?;
        // `asset_path` hands back the file itself; its parent is the
        // directory `load_from` joins against. The parent always exists in
        // practice (resolution joins a file onto a directory), but there is
        // no `unwrap` on that assumption — a bare name refuses by name.
        let dir = path.parent().ok_or_else(|| {
            CoreError::invalid(format!(
                "asset {} ({}) resolved to a path with no parent directory",
                self.label(),
                self.asset_file()
            ))
        })?;
        self.load_from(dir)
    }

    /// Load this payload from `dir`, verifying exact size and SHA-256
    /// against the pinned values.
    ///
    /// A missing file refuses as [`CoreError::InvalidInput`] naming the
    /// resource label, the file name, the directory path and the
    /// underlying error. An unreadable file (EACCES, EISDIR) refuses the
    /// same way — as `InvalidInput` carrying the OS error text rather
    /// than an `Io` error — because [`CoreError::Io`] cannot name the
    /// resource (its `Display` is fixed to path plus source), and a log
    /// line must say which of the 27 payloads is absent. A size or
    /// digest mismatch refuses through the shared `verify_payload`
    /// check, naming the resource label, the file name, and both the
    /// expected and actual numbers/digests.
    pub fn load_from(&self, dir: &Path) -> Result<Vec<u8>> {
        let path = dir.join(self.asset_file());
        let bytes = std::fs::read(&path).map_err(|source| {
            CoreError::invalid(format!(
                "payload {} ({}) cannot be read from '{}': {source}",
                self.label(),
                self.asset_file(),
                path.display()
            ))
        })?;
        super::verify_payload(
            self.label(),
            self.asset_file(),
            self.size(),
            self.sha256(),
            &bytes,
        )?;
        Ok(bytes)
    }
}

/// The payloads `ExtractFreeDOS` writes to `destination`, in id order:
/// the 2 root files or the 25 `LOCALE\` files.
pub fn files_for(destination: Destination) -> impl Iterator<Item = FreeDosFile> {
    FreeDosFile::ALL
        .iter()
        .copied()
        .filter(move |file| file.destination() == destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Algo;
    use crate::hash::hash_reader;

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
    fn every_file_loads_with_pinned_size_and_digest() {
        // The anti-drift guard: the file names, sizes and digests above
        // come from `assets/manifest.json`, so a manifest regeneration
        // that changes any of the 27 payloads fails here until the enum
        // is updated in lockstep.
        for file in FreeDosFile::ALL {
            let bytes = file
                .load_from(&resources_dir())
                .expect("the pinned payload loads");
            assert_eq!(
                bytes.len() as u64,
                file.size(),
                "loaded length of {} matches the pinned size",
                file.asset_file()
            );
            let actual = hash_reader(Algo::Sha256, bytes.as_slice()).expect("in-memory bytes hash");
            assert_eq!(
                actual,
                file.sha256(),
                "SHA-256 of {} matches the pinned digest",
                file.asset_file()
            );
        }
    }

    #[test]
    fn ids_are_300_through_326_with_no_gaps() {
        // `ALL` in id order with no gaps or duplicates: exactly the
        // upstream `RCDATA` range (`src/resource.h:34-60`).
        let ids: Vec<u32> = FreeDosFile::ALL.iter().map(|file| file.id()).collect();
        let want: Vec<u32> = (300..=326).collect();
        assert_eq!(ids, want, "the 27 ids are 300..=326 in order");
    }

    #[test]
    fn asset_files_are_the_pinned_rcdata_names() {
        // One assertion over every variant, so a future variant that is
        // added to `ALL` without a real payload file cannot slip past
        // the load test above (it would fail there on a missing file).
        let files: Vec<&str> = FreeDosFile::ALL
            .iter()
            .map(|file| file.asset_file())
            .collect();
        assert_eq!(
            files,
            [
                "RCDATA_300.bin",
                "RCDATA_301.bin",
                "RCDATA_302.bin",
                "RCDATA_303.bin",
                "RCDATA_304.bin",
                "RCDATA_305.bin",
                "RCDATA_306.bin",
                "RCDATA_307.bin",
                "RCDATA_308.bin",
                "RCDATA_309.bin",
                "RCDATA_310.bin",
                "RCDATA_311.bin",
                "RCDATA_312.bin",
                "RCDATA_313.bin",
                "RCDATA_314.bin",
                "RCDATA_315.bin",
                "RCDATA_316.bin",
                "RCDATA_317.bin",
                "RCDATA_318.bin",
                "RCDATA_319.bin",
                "RCDATA_320.bin",
                "RCDATA_321.bin",
                "RCDATA_322.bin",
                "RCDATA_323.bin",
                "RCDATA_324.bin",
                "RCDATA_325.bin",
                "RCDATA_326.bin",
            ],
            "the 27 pinned file names"
        );
    }

    #[test]
    fn target_names_are_the_27_upstream_names() {
        // The `res_name[]` table (`src/dos.c:346-351`) pinned whole: id
        // 320 keeps its `.CPX` extension (see the module docs), so a
        // future edit borrowing the extensionless `ega12` picker string
        // fails here.
        let names: Vec<&str> = FreeDosFile::ALL
            .iter()
            .map(|file| file.target_name())
            .collect();
        assert_eq!(
            names,
            [
                "COMMAND.COM",
                "KERNEL.SYS",
                "DISPLAY.EXE",
                "KEYB.EXE",
                "MODE.COM",
                "KEYBOARD.SYS",
                "KEYBRD2.SYS",
                "KEYBRD3.SYS",
                "KEYBRD4.SYS",
                "EGA.CPX",
                "EGA2.CPX",
                "EGA3.CPX",
                "EGA4.CPX",
                "EGA5.CPX",
                "EGA6.CPX",
                "EGA7.CPX",
                "EGA8.CPX",
                "EGA9.CPX",
                "EGA10.CPX",
                "EGA11.CPX",
                "EGA12.CPX",
                "EGA13.CPX",
                "EGA14.CPX",
                "EGA15.CPX",
                "EGA16.CPX",
                "EGA17.CPX",
                "EGA18.CPX",
            ],
            "the 27 upstream file names"
        );
    }

    #[test]
    fn destination_split_matches_the_reference() {
        // `(i<2) ? path : locale_path` (`src/dos.c:377`): exactly the
        // first two resources land at the root.
        let root: Vec<FreeDosFile> = files_for(Destination::Root).collect();
        assert_eq!(
            root,
            [FreeDosFile::CommandCom, FreeDosFile::KernelSys],
            "the root holds COMMAND.COM and KERNEL.SYS"
        );
        let locale: Vec<FreeDosFile> = files_for(Destination::Locale).collect();
        assert_eq!(locale.len(), 25, "the locale holds the other 25");
        let mut want: Vec<FreeDosFile> = FreeDosFile::ALL
            .iter()
            .copied()
            .filter(|file| *file != FreeDosFile::CommandCom && *file != FreeDosFile::KernelSys)
            .collect();
        assert_eq!(locale, want, "the locale files run in id order");
        want.insert(0, FreeDosFile::KernelSys);
        want.insert(0, FreeDosFile::CommandCom);
        assert_eq!(
            want,
            FreeDosFile::ALL,
            "root plus locale cover every payload exactly once"
        );
    }

    #[test]
    fn missing_file_errors_as_invalid_input_naming_resource_and_file() {
        // An empty directory and a 26-of-27 scratch copy both refuse as
        // `InvalidInput` naming the resource label and the file in
        // ASCII, so the log says which payload is absent; the variant
        // assert pins `InvalidInput` so a regression to `Io` with the
        // same text still fails.
        fn check(file: FreeDosFile, dir: &Path) {
            let error = file.load_from(dir).expect_err("a missing payload refuses");
            assert!(
                matches!(error, CoreError::InvalidInput { .. }),
                "a missing payload is InvalidInput: {error}"
            );
            let text = error.to_string();
            assert!(
                text.contains(file.label()),
                "the error names the resource: {text}"
            );
            assert!(
                text.contains(file.asset_file()),
                "the error names the file: {text}"
            );
            assert!(text.is_ascii(), "the error stays ASCII: {text}");
        }
        let empty = tempfile::tempdir().expect("scratch fits");
        for file in FreeDosFile::ALL {
            check(file, empty.path());
        }
        let omitted = FreeDosFile::Ega18;
        let scratch = tempfile::tempdir().expect("scratch fits");
        for file in FreeDosFile::ALL {
            if file != omitted {
                std::fs::copy(
                    resources_dir().join(file.asset_file()),
                    scratch.path().join(file.asset_file()),
                )
                .expect("the fixture copies");
            }
        }
        check(omitted, scratch.path());
    }

    #[test]
    fn truncated_file_errors_naming_both_byte_counts() {
        // Copy a real payload and truncate it: the size check fires
        // before the digest, naming the file and both counts.
        let file = FreeDosFile::CommandCom;
        let bytes =
            std::fs::read(resources_dir().join(file.asset_file())).expect("the pinned file reads");
        let scratch = tempfile::tempdir().expect("scratch fits");
        let kept = bytes.len().saturating_sub(12);
        std::fs::write(scratch.path().join(file.asset_file()), &bytes[..kept])
            .expect("the truncated copy writes");
        let error = file
            .load_from(scratch.path())
            .expect_err("a truncated payload refuses");
        let text = error.to_string();
        assert!(
            text.contains(file.label()),
            "the error names the resource: {text}"
        );
        assert!(
            text.contains(file.asset_file()),
            "the error names the file: {text}"
        );
        assert!(
            text.contains(&kept.to_string()),
            "the error names the actual count: {text}"
        );
        assert!(
            text.contains(&file.size().to_string()),
            "the error names the expected count: {text}"
        );
        assert!(text.is_ascii(), "the error stays ASCII: {text}");
    }

    #[test]
    fn flipped_byte_errors_naming_both_digests() {
        // Copy a real payload with one byte flipped at the same size:
        // the digest check fires, naming the file and both digests.
        let file = FreeDosFile::Ega;
        let mut bytes =
            std::fs::read(resources_dir().join(file.asset_file())).expect("the pinned file reads");
        bytes[0] ^= 0x01;
        let scratch = tempfile::tempdir().expect("scratch fits");
        std::fs::write(scratch.path().join(file.asset_file()), &bytes)
            .expect("the flipped copy writes");
        let error = file
            .load_from(scratch.path())
            .expect_err("a flipped payload refuses");
        let text = error.to_string();
        assert!(
            text.contains(file.label()),
            "the error names the resource: {text}"
        );
        assert!(
            text.contains(file.asset_file()),
            "the error names the file: {text}"
        );
        let actual = hash_reader(Algo::Sha256, bytes.as_slice()).expect("the flipped bytes hash");
        assert_ne!(actual, file.sha256(), "the flip changes the digest");
        assert!(
            text.contains(&actual),
            "the error names the actual digest: {text}"
        );
        assert!(
            text.contains(file.sha256()),
            "the error names the expected digest: {text}"
        );
        assert!(text.is_ascii(), "the error stays ASCII: {text}");
    }

    #[test]
    fn labels_and_names_stay_ascii() {
        // Every literal below rides an error or assertion message, so all
        // of them pin ASCII here rather than one formatting call at a time.
        for file in FreeDosFile::ALL {
            assert!(
                file.label().is_ascii(),
                "the label stays ASCII: {}",
                file.asset_file()
            );
            assert!(
                file.target_name().is_ascii(),
                "the target name stays ASCII: {}",
                file.asset_file()
            );
            assert!(
                file.asset_file().is_ascii(),
                "the asset file stays ASCII: {}",
                file.asset_file()
            );
        }
    }
}
