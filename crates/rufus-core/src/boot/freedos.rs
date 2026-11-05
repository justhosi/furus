//! FreeDOS install: the 27 embedded payloads, the `CONFIG.SYS` /
//! `AUTOEXEC.BAT` pair and the FAT32 boot record — a complete FreeDOS
//! volume from [`install`].
//!
//! Reference behaviour (`ExtractFreeDOS`, `src/dos.c:344-403`): the
//! reference creates `LOCALE\` on the target, writes the first two
//! resources (`COMMAND.COM`, `KERNEL.SYS`) to the target root with
//! hidden+system attributes and the other 25 into `LOCALE\` with
//! normal attributes (`(i<2) ? path : locale_path`, `src/dos.c:344-381`),
//! then finishes with `SetDOSLocale(path, TRUE)` (`src/dos.c:403`),
//! which plans the keyboard/codepage/EGA choice and the byte-exact
//! `CONFIG.SYS` / `AUTOEXEC.BAT` contents (see
//! [`dos_locale`](super::dos_locale)). The boot record lands where
//! `WritePBR` puts it (`src/format.c:1006-1040`, the `BT_FREEDOS`
//! branch at `:1033`). [`install`] follows that order — the payloads
//! in id order, then the locale files, then the record — and the
//! record goes through the BPB-preserving graft
//! ([`records::write`](super::records::write)): the record's entry and
//! code win, the volume's own `0x0B..0x5A` geometry — volume label
//! included — survives, and sectors 1 (FSInfo) and 2 are untouched.
//! The boot record runs last, the same invariant every installer in
//! this crate keeps: a refusal anywhere earlier (a foreign file in the
//! way) leaves sector 0 with the formatter's record, never a
//! half-bootable stick. Nothing here flushes: the caller owns the
//! flush, the same convention as the [`kolibri`](super::kolibri) and
//! [`msdos`](super::msdos) installers.
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
//! Layout, matching the reference exactly: [`FreeDosFile::destination`]
//! sends the first two resources to the target root and the other 25
//! into `LOCALE\` (`(i<2) ? path : locale_path`, `src/dos.c:377`).
//! Every write keeps the keep-if-identical policy of
//! [`install_loader`](super::kolibri::install_loader): a file already
//! present with byte-identical content counts as kept and nothing is
//! written; differing bytes refuse naming the file. (The reference
//! overwrites with `CREATE_ALWAYS`; this crate never overwrites a
//! foreign DOS file.) Declared gap: our
//! [`Fat32`](crate::fs::fat32::Fat32) `create_file` carries no attribute
//! parameter (every entry takes the plain archive attribute), so the
//! reference's hidden+system marks on `COMMAND.COM` / `KERNEL.SYS`
//! cannot be reproduced through that API yet.
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
//! the boot record is not in this set: boot-record handling comes from
//! ms-sys, per `license.h`, so the record lives in
//! [`records`](super::records) instead, transcribed from the ms-sys
//! headers. The `UPX!` bytes are
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
//! Honest limits that remain. FAT attributes (hidden+system on
//! `COMMAND.COM` / `KERNEL.SYS`) cannot be set because
//! [`Fat32`](crate::fs::fat32::Fat32) `create_file` takes no attribute
//! parameter. FAT16 media are out of scope: this crate formats FAT32
//! only. And the record is verified by transcription plus `fsck.fat`,
//! never by booting — there is no QEMU on this host, so no stick has
//! booted on hardware.
//!
//! One deliberate divergence from the reference, stated plainly.
//! `write_fat_32_fd_br` (`src/ms-sys/fat32.c:101-125`, called with
//! `bKeepLabel = 0`) also rewrites sector 1 from its header's FSInfo
//! image and zeroes sector 2 except `55 AA` — purely so
//! 1024/2048-byte-sector media see a boot signature at `0x3FE`/`0x5FE`
//! (that is what ms-sys `is_fat_32_br` checks) — but it deliberately
//! leaves the 8 FSInfo count bytes at absolute `0x3E8..0x3F0`
//! unwritten (`Cluster information is not overwritten`, says the
//! ms-sys comment: it writes `0x52..0x3E8` and `0x3F0..0x600`), so the
//! formatter's real free-cluster counts survive there. Our volumes use
//! 512-byte sectors, the BIOS loads only sector 0, and
//! [`install_boot_record`] preserves both sectors instead of
//! rewriting them. This is a fidelity difference with a reason, not
//! an omission. The FreeDOS FAT16 record is out of scope: this project
//! formats FAT32 only.
//!
//! All error and assertion text is ASCII.

use std::path::Path;

use super::dos_locale;
use super::records;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::fat32::Fat32;
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

/// Write the FreeDOS FAT32 boot record onto the volume's boot sector:
/// the `write_fat_32_fd_br` payload as transcribed in
/// [`records`](super::records) (head at `0x0`, the ANI/FreeDOS boot
/// code at `0x52`, `55 AA` at `0x1FE`).
///
/// Goes through the BPB-preserving graft
/// ([`records::write`](super::records::write)): the record's entry
/// and code win, the volume's own `0x0B..0x5A` geometry — volume
/// label included — survives, and sectors 1 (FSInfo) and 2 are
/// untouched, unlike the reference's blank-FSInfo rewrite (see the
/// module docs for why). Does not flush: the caller owns the flush.
pub fn install_boot_record(fat: &mut Fat32) -> Result<()> {
    records::write(fat, &records::freedos_fat32())
}

/// Directory holding the 25 locale payloads (`LOCALE\` of
/// `ExtractFreeDOS`, `src/dos.c:369-372`): every [`FreeDosFile`] with
/// [`Destination::Locale`] lands here.
pub const LOCALE_DIR: &str = "/LOCALE";

/// The locale directory's bare name, for root-listing comparisons.
pub const LOCALE_NAME: &str = "LOCALE";

/// File name of the DOS configuration at the volume root.
pub const CONFIG_SYS: &str = "CONFIG.SYS";

/// File name of the DOS startup batch file at the volume root.
pub const AUTOEXEC_BAT: &str = "AUTOEXEC.BAT";

/// Destination path of `CONFIG.SYS` on the volume: the volume root.
pub const CONFIG_SYS_PATH: &str = "/CONFIG.SYS";

/// Destination path of `AUTOEXEC.BAT` on the volume: the volume root.
pub const AUTOEXEC_BAT_PATH: &str = "/AUTOEXEC.BAT";

/// One file [`install`] wrote: its volume name and byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrittenFile {
    name: &'static str,
    bytes: u64,
}

impl WrittenFile {
    /// Volume file name (`COMMAND.COM`, `EGA.CPX`, `CONFIG.SYS`, ...).
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Bytes written.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// What [`install`] did: which files were written (each with its byte
/// count), which were kept, and whether the boot record went down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    written: Vec<WrittenFile>,
    kept: Vec<&'static str>,
    record_written: bool,
}

impl Installed {
    /// Files written, in install order, each with its byte count. Kept
    /// files contribute no entry here.
    #[must_use]
    pub fn written(&self) -> &[WrittenFile] {
        &self.written
    }

    /// Names of the files that already held byte-identical content and
    /// were kept without a write, in install order.
    #[must_use]
    pub fn kept(&self) -> &[&str] {
        &self.kept
    }

    /// Total bytes written (kept files contribute nothing).
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.written.iter().map(WrittenFile::bytes).sum()
    }

    /// Whether the boot record was grafted onto sector 0. Always true
    /// on success: the record write is unconditional and runs last, so
    /// a repeat install rewrites the same bytes rather than skipping
    /// them.
    #[must_use]
    pub fn record_written(&self) -> bool {
        self.record_written
    }
}

/// Create `LOCALE` at the volume root when it is absent.
///
/// The [`install_companions`](super::syslinux::install_companions)
/// idiom: the root listing decides, so an existing directory is left
/// alone and a second install never recreates it. A root entry of that
/// name that is a file refuses naming it instead of failing inside
/// `mkdir` or the later locale writes.
fn ensure_locale_dir(fat: &mut Fat32) -> Result<()> {
    let root = fat.list_dir("/")?;
    match root.iter().find(|entry| {
        entry.name.eq_ignore_ascii_case(LOCALE_NAME)
            || entry.short_name.eq_ignore_ascii_case(LOCALE_NAME)
    }) {
        Some(entry) if entry.is_dir => Ok(()),
        Some(_) => Err(CoreError::invalid(format!(
            "freedos directory '{LOCALE_NAME}' already present at '/' as a file, not a directory: refusing"
        ))),
        None => {
            fat.mkdir(LOCALE_DIR)?;
            Ok(())
        }
    }
}

/// Place one file at `dest` inside `dir`: keep without a write when an
/// entry of `name` (case-insensitive name or short name) already holds
/// byte-identical content, refuse naming the file when it holds
/// different bytes, else write `bytes` (`create_file` plus a
/// zero-offset `write_at`).
///
/// Shared by the payload loop and the locale files, the same policy as
/// [`install_loader`](super::kolibri::install_loader): silently
/// keeping a foreign DOS file would boot it, so a conflict refuses
/// instead.
fn place(
    fat: &mut Fat32,
    dir: &str,
    dest: &str,
    name: &'static str,
    bytes: &[u8],
    written: &mut Vec<WrittenFile>,
    kept: &mut Vec<&'static str>,
) -> Result<()> {
    let len = u64::try_from(bytes.len()).map_err(|_| {
        CoreError::invalid(format!(
            "freedos file '{name}' is longer than u64: refusing"
        ))
    })?;
    let present = fat.list_dir(dir)?.iter().any(|entry| {
        entry.name.eq_ignore_ascii_case(name) || entry.short_name.eq_ignore_ascii_case(name)
    });
    if present {
        let back = fat.read_file(dest)?;
        if back.as_slice() == bytes {
            kept.push(name);
            return Ok(());
        }
        return Err(CoreError::invalid(format!(
            "freedos file '{name}' already present at '{dir}' differs from the installer copy: refusing to overwrite it"
        )));
    }
    fat.create_file(dest, len)?;
    fat.write_at(dest, 0, bytes)?;
    written.push(WrittenFile { name, bytes: len });
    Ok(())
}

/// Install a complete FreeDOS volume: the 27 payloads in id order (the
/// two [`Destination::Root`] files at `/COMMAND.COM` and `/KERNEL.SYS`,
/// the 25 [`Destination::Locale`] files under `/LOCALE`), then the
/// locale files [`dos_locale::plan`] renders for
/// [`DosFlavor::FreeDos`](dos_locale::DosFlavor) (`/CONFIG.SYS` when
/// the plan carries one, `/AUTOEXEC.BAT` always), then the boot record
/// through [`records::write`](super::records::write).
///
/// The record runs last — the "boot record last" invariant every
/// installer in this crate follows — so a refusal anywhere earlier
/// leaves sector 0 with the formatter's record. A failure between
/// files leaves a partial set behind (the torn-state window, the same
/// as the [`msdos`](super::msdos) installer), but with no record down
/// nothing is half-bootable. Does not flush: the caller owns the
/// flush.
pub fn install(fat: &mut Fat32, locale: &dos_locale::Locale) -> Result<Installed> {
    install_from(fat, locale, &|file| file.load())
}

/// Install a complete FreeDOS volume, resolving the payloads through
/// `load`.
///
/// The single loading path behind [`install`] (which passes
/// [`FreeDosFile::load`]): callers that resolve payloads differently —
/// the tests point it at the asset tree without the runtime asset
/// directory — inject that here instead of duplicating the install,
/// the same seam as
/// [`install_payloads_from`](super::syslinux::install_payloads_from).
pub fn install_from(
    fat: &mut Fat32,
    locale: &dos_locale::Locale,
    load: &dyn Fn(FreeDosFile) -> Result<Vec<u8>>,
) -> Result<Installed> {
    ensure_locale_dir(fat)?;
    let mut written = Vec::new();
    let mut kept: Vec<&'static str> = Vec::new();
    for file in FreeDosFile::ALL {
        let bytes = load(file)?;
        let name = file.target_name();
        match file.destination() {
            Destination::Root => {
                let dest = format!("/{name}");
                place(fat, "/", &dest, name, &bytes, &mut written, &mut kept)?;
            }
            Destination::Locale => {
                let dest = format!("{LOCALE_DIR}/{name}");
                place(
                    fat,
                    LOCALE_DIR,
                    &dest,
                    name,
                    &bytes,
                    &mut written,
                    &mut kept,
                )?;
            }
        }
    }
    let plan = dos_locale::plan(dos_locale::DosFlavor::FreeDos, locale);
    if let Some(config) = plan.config_sys() {
        place(
            fat,
            "/",
            CONFIG_SYS_PATH,
            CONFIG_SYS,
            config,
            &mut written,
            &mut kept,
        )?;
    }
    place(
        fat,
        "/",
        AUTOEXEC_BAT_PATH,
        AUTOEXEC_BAT,
        plan.autoexec_bat(),
        &mut written,
        &mut kept,
    )?;
    records::write(fat, &records::freedos_fat32())?;
    Ok(Installed {
        written,
        kept,
        record_written: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::dos_locale::DosFlavor;
    use crate::boot::dos_locale::Locale;
    use crate::boot::dos_locale::plan;
    use crate::fs::Volume;
    use crate::fs::fat32::format::FormatOptions;
    use crate::hash::Algo;
    use crate::hash::hash_reader;
    use std::cell::RefCell;
    use std::rc::Rc;

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

    /// A [`Volume`] over shared bytes, the same shim the kolibri
    /// installer tests use: `Fat32` keeps its store private, so the
    /// tests watch the image through the shared handle.
    #[derive(Debug, Clone)]
    struct SharedVolume {
        bytes: Rc<RefCell<Vec<u8>>>,
    }

    impl SharedVolume {
        fn blank(len: u64) -> Self {
            let size = usize::try_from(len).expect("the ram size fits usize");
            Self {
                bytes: Rc::new(RefCell::new(vec![0u8; size])),
            }
        }
    }

    impl Volume for SharedVolume {
        fn total_bytes(&self) -> u64 {
            self.bytes.borrow().len() as u64
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            let borrowed = self.bytes.borrow();
            let start = usize::try_from(offset).expect("the test offset fits usize");
            let end = start.checked_add(buf.len()).expect("the test window fits");
            let window = borrowed.get(start..end).expect("the test read fits");
            buf.copy_from_slice(window);
            Ok(())
        }

        fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
            let mut borrowed = self.bytes.borrow_mut();
            let start = usize::try_from(offset).expect("the test offset fits usize");
            let end = start.checked_add(buf.len()).expect("the test write fits");
            let window = borrowed.get_mut(start..end).expect("the test write fits");
            window.copy_from_slice(buf);
            Ok(())
        }
    }

    /// A freshly formatted 64 MiB volume plus the shared handle that
    /// still observes its bytes.
    fn formatted() -> (SharedVolume, Fat32) {
        let backing = SharedVolume::blank(64 * 1024 * 1024);
        let fat = Fat32::format(
            Box::new(backing.clone()),
            &FormatOptions {
                volume_id: 0x1234_5678,
                ..Default::default()
            },
        )
        .expect("the volume formats");
        (backing, fat)
    }

    /// A copy of one 512-byte sector of the image under test.
    fn sector(backing: &SharedVolume, index: usize) -> [u8; 512] {
        let borrowed = backing.bytes.borrow();
        let start = index.checked_mul(512).expect("the test offset fits");
        let window = borrowed
            .get(start..start + 512)
            .expect("the test sector fits");
        let mut sector = [0u8; 512];
        sector.copy_from_slice(window);
        sector
    }

    #[test]
    fn install_boot_record_writes_the_freedos_sector() {
        // The record proof on a real 64 MiB image: the payload head
        // and code land through the graft, the whole `0x0B..0x5A` BPB
        // window (label included) survives byte-identical — the graft
        // takes only the record's `0x00..0x0B` entry and `0x5A..0x1FE`
        // code, so the payload legitimately owns exactly those two
        // windows — the `55 AA` tail closes the sector, sectors 1
        // (FSInfo, real counts kept) and 2 are byte-identical to
        // before the call (the deliberate divergence from the
        // reference's blank-FSInfo rewrite, see the module docs), a
        // second write changes nothing, and the jump really moved off
        // the formatter's own `EB 3C 90` (the OEM name is `MSWIN4.1`
        // on both sides, so the jump — not the OEM — is the
        // discriminator). The dumped image is `fsck.fat` clean; the
        // tool resolves through `PATH` and the test skips when absent.
        let (backing, mut fat) = formatted();
        fat.flush().expect("the pre-write flush runs");
        let before = sector(&backing, 0);
        let before_fsinfo = sector(&backing, 1);
        let before_second = sector(&backing, 2);
        install_boot_record(&mut fat).expect("the record writes");
        let record = crate::boot::records::freedos_fat32();
        let after = sector(&backing, 0);
        assert_eq!(
            &after[0..11],
            &record[0..11],
            "the payload jump and oem name win"
        );
        assert_eq!(
            &after[11..90],
            &before[11..90],
            "the graft keeps the whole bpb window, label included"
        );
        assert_eq!(
            &after[90..510],
            &record[90..510],
            "the boot code is the payload's"
        );
        assert_eq!(
            &after[510..512],
            &[0x55, 0xAA],
            "the signature closes the sector"
        );
        assert_eq!(
            sector(&backing, 1),
            before_fsinfo,
            "the write preserves the fsinfo sector with its real counts"
        );
        assert_eq!(
            sector(&backing, 2),
            before_second,
            "the write preserves sector 2"
        );
        assert_eq!(
            &before[0..3],
            &[0xEB, 0x3C, 0x90],
            "the formatter's own jump"
        );
        assert_eq!(
            &after[0..3],
            &[0xEB, 0x58, 0x90],
            "the payload jump replaces it"
        );
        install_boot_record(&mut fat).expect("the second write runs");
        assert_eq!(sector(&backing, 0), after, "a second write changes nothing");
        fat.flush().expect("the caller-side flush runs");
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join("freedos-record.img");
        std::fs::write(&image, backing.bytes.borrow().as_slice()).expect("the image dumps");
        let output = match std::process::Command::new("fsck.fat")
            .arg("-n")
            .arg(&image)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                eprintln!("skip: the fsck acceptance needs fsck.fat on PATH ({error})");
                return;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "fsck.fat -n exits 0 after the record write ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }

    /// Install through [`install_from`](super::install_from) with the
    /// payloads read straight from the asset tree: the production
    /// [`install`](super::install) resolves through the runtime asset
    /// directory, which no test may depend on, so the tests inject
    /// this loader instead (the same seam as
    /// `syslinux::install_payloads_from`).
    fn install_assets(fat: &mut Fat32, locale: &Locale) -> Result<Installed> {
        let dir = resources_dir();
        install_from(fat, locale, &|file| file.load_from(&dir))
    }

    /// Volume path of a payload: the root pair at `/`, the other 25
    /// under `/LOCALE`.
    fn payload_dest(file: FreeDosFile) -> String {
        match file.destination() {
            Destination::Root => format!("/{}", file.target_name()),
            Destination::Locale => format!("/LOCALE/{}", file.target_name()),
        }
    }

    /// The 25 locale payload names in id order, the exact `/LOCALE`
    /// listing a fresh install produces.
    fn locale_names() -> Vec<&'static str> {
        FreeDosFile::ALL
            .iter()
            .filter(|file| file.destination() == Destination::Locale)
            .map(|file| file.target_name())
            .collect()
    }

    /// Dump the image under test and require `fsck.fat -n` (read-only)
    /// to exit 0. The tool resolves through `PATH`; when it is absent
    /// the test skips. The caller flushes first: nothing in this module
    /// flushes, so the image dumps only what the caller published.
    fn assert_fsck_clean(backing: &SharedVolume, name: &str) {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join(name);
        std::fs::write(&image, backing.bytes.borrow().as_slice()).expect("the image dumps");
        let output = match std::process::Command::new("fsck.fat")
            .arg("-n")
            .arg(&image)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                eprintln!("skip: the fsck acceptance needs fsck.fat on PATH ({error})");
                return;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "fsck.fat -n exits 0 after the freedos install ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }

    #[test]
    fn install_us_builds_the_full_volume() {
        // End to end with the US locale (the 437/US special case, so no
        // CONFIG.SYS): the root holds the pair, the echo-only
        // AUTOEXEC.BAT and LOCALE; LOCALE holds exactly the 25 locale
        // payload names; every payload reads back byte-identical to its
        // asset; AUTOEXEC.BAT equals the plan bytes; the boot record
        // lands through the graft with sectors 1-2 untouched; and the
        // image is fsck clean.
        let locale = Locale::us();
        let planned = plan(DosFlavor::FreeDos, &locale);
        assert!(
            planned.config_sys().is_none(),
            "the US plan carries no CONFIG.SYS"
        );
        let (backing, mut fat) = formatted();
        fat.flush().expect("the pre-install flush runs");
        let before = sector(&backing, 0);
        let before_fsinfo = sector(&backing, 1);
        let before_second = sector(&backing, 2);
        let done = install_assets(&mut fat, &locale).expect("the install runs");
        assert!(done.kept().is_empty(), "a fresh install keeps nothing");
        assert!(done.record_written(), "the record went down");
        // The report: the 27 payloads in id order, then AUTOEXEC.BAT —
        // no CONFIG.SYS, because the plan carries none.
        let mut want: Vec<&str> = FreeDosFile::ALL
            .iter()
            .map(|file| file.target_name())
            .collect();
        want.push(AUTOEXEC_BAT);
        let written: Vec<&str> = done.written().iter().map(|file| file.name()).collect();
        assert_eq!(
            written, want,
            "every payload plus AUTOEXEC.BAT wrote in order"
        );
        for (file, entry) in FreeDosFile::ALL.iter().zip(done.written().iter()) {
            assert_eq!(
                entry.bytes(),
                file.size(),
                "the report counts the {} bytes",
                file.target_name()
            );
        }
        let autoexec = done.written().last().expect("AUTOEXEC.BAT wrote");
        assert_eq!(
            autoexec.name(),
            AUTOEXEC_BAT,
            "the last write is AUTOEXEC.BAT"
        );
        assert_eq!(
            autoexec.bytes(),
            planned.autoexec_bat().len() as u64,
            "the report counts the AUTOEXEC.BAT bytes"
        );
        let total: u64 = FreeDosFile::ALL
            .iter()
            .map(|file| file.size())
            .sum::<u64>()
            .checked_add(planned.autoexec_bat().len() as u64)
            .expect("the byte total fits u64");
        assert_eq!(
            done.bytes_written(),
            total,
            "the total counts every written byte"
        );
        // The root holds the pair, the startup file and the locale
        // directory — and no CONFIG.SYS.
        let listed = fat.list_dir("/").expect("the root lists");
        let mut shorts: Vec<&str> = listed
            .iter()
            .map(|entry| entry.short_name.as_str())
            .collect();
        shorts.sort_unstable();
        assert_eq!(
            shorts,
            ["AUTOEXEC.BAT", "COMMAND.COM", "KERNEL.SYS", "LOCALE"],
            "the root holds the pair, the startup file and LOCALE"
        );
        assert!(
            fat.read_file("/CONFIG.SYS").is_err(),
            "no CONFIG.SYS was created"
        );
        // LOCALE holds exactly the 25 locale payload names.
        let listed = fat.list_dir("/LOCALE").expect("the locale lists");
        let names: Vec<&str> = listed
            .iter()
            .map(|entry| entry.short_name.as_str())
            .collect();
        assert_eq!(names, locale_names(), "LOCALE holds the 25 locale files");
        // Every payload reads back byte-identical to its asset.
        for file in FreeDosFile::ALL {
            let want =
                std::fs::read(resources_dir().join(file.asset_file())).expect("the asset reads");
            let back = fat
                .read_file(&payload_dest(file))
                .expect("the payload reads back");
            assert_eq!(
                back,
                want,
                "payload {} is byte-identical to its asset",
                file.target_name()
            );
        }
        let back = fat
            .read_file("/AUTOEXEC.BAT")
            .expect("AUTOEXEC.BAT reads back");
        assert_eq!(
            back,
            planned.autoexec_bat(),
            "AUTOEXEC.BAT equals the plan bytes"
        );
        // The record proof: the FreeDOS head and code land, the BPB
        // window survives, the signature closes the sector, and sectors
        // 1 (FSInfo, real counts kept) and 2 are byte-identical to
        // before the call.
        let after = sector(&backing, 0);
        assert_eq!(
            &after[0..3],
            &[0xEB, 0x58, 0x90],
            "the payload jump replaces the formatter's"
        );
        assert_eq!(&after[0x52..0x5A], b"FAT32   ", "the type string at 0x52");
        assert_eq!(
            &after[510..512],
            &[0x55, 0xAA],
            "the signature closes the sector"
        );
        assert_eq!(
            &after[11..90],
            &before[11..90],
            "the graft keeps the whole bpb window, label included"
        );
        assert_eq!(
            sector(&backing, 1),
            before_fsinfo,
            "the install preserves the fsinfo sector with its real counts"
        );
        assert_eq!(
            sector(&backing, 2),
            before_second,
            "the install preserves sector 2"
        );
        fat.flush().expect("the caller-side flush runs");
        assert_fsck_clean(&backing, "freedos-install.img");
    }

    #[test]
    fn us_special_case_writes_no_config_sys() {
        // The 437/US special case (`dos_locale.c:1008-1023`): the plan
        // carries no CONFIG.SYS and the 93-byte echo-only AUTOEXEC.BAT,
        // so the install writes no CONFIG.SYS anywhere.
        let locale = Locale::us();
        let planned = plan(DosFlavor::FreeDos, &locale);
        assert!(
            planned.config_sys().is_none(),
            "the 437/US plan carries no CONFIG.SYS"
        );
        assert_eq!(
            planned.autoexec_bat().len(),
            93,
            "the echo-only AUTOEXEC.BAT is 93 bytes"
        );
        let (_backing, mut fat) = formatted();
        let done = install_assets(&mut fat, &locale).expect("the install runs");
        let listed = fat.list_dir("/").expect("the root lists");
        assert!(
            listed.iter().all(|entry| entry.short_name != "CONFIG.SYS"),
            "the root has no CONFIG.SYS"
        );
        assert!(
            fat.read_file("/CONFIG.SYS").is_err(),
            "no CONFIG.SYS was created"
        );
        let back = fat
            .read_file("/AUTOEXEC.BAT")
            .expect("AUTOEXEC.BAT reads back");
        assert_eq!(
            back,
            planned.autoexec_bat(),
            "AUTOEXEC.BAT is the 93-byte echo form"
        );
        assert_eq!(back.len(), 93, "the echo form stays 93 bytes on disk");
        assert!(
            done.written()
                .iter()
                .all(|file| file.name() != "CONFIG.SYS"),
            "the report writes no CONFIG.SYS"
        );
        assert!(
            done.kept().iter().all(|kept| *kept != "CONFIG.SYS"),
            "the report keeps no CONFIG.SYS"
        );
    }

    #[test]
    fn non_us_locale_writes_byte_exact_dos_files() {
        // German keyboard with a Latin-1 OEM codepage: exercises the
        // FreeDOS 850-to-858 upgrade, so CONFIG.SYS and AUTOEXEC.BAT
        // must equal the plan byte for byte and the startup file must
        // name the upgraded codepage, the locale EGA file and the
        // keyboard driver the plan picked.
        let locale = Locale {
            keyboard_id: 0x0407,
            system_language_id: 0x0409,
            oem_codepage: 850,
        };
        let planned = plan(DosFlavor::FreeDos, &locale);
        assert_eq!(planned.keyboard(), "gr", "German survives");
        assert_eq!(planned.codepage(), 858, "the 850 upgrade lands");
        assert_eq!(planned.ega_file(), "ega.cpx", "the EGA file");
        let config = planned
            .config_sys()
            .expect("a non-US plan carries CONFIG.SYS");
        let (_backing, mut fat) = formatted();
        let done = install_assets(&mut fat, &locale).expect("the install runs");
        let back = fat.read_file("/CONFIG.SYS").expect("CONFIG.SYS reads back");
        assert_eq!(back, config, "CONFIG.SYS is byte-exact");
        let back = fat
            .read_file("/AUTOEXEC.BAT")
            .expect("AUTOEXEC.BAT reads back");
        assert_eq!(back, planned.autoexec_bat(), "AUTOEXEC.BAT is byte-exact");
        let text = String::from_utf8(back).expect("AUTOEXEC.BAT is ASCII text");
        assert!(
            text.contains("((858) \\locale\\ega.cpx)"),
            "the prepare line names the upgraded codepage and EGA file: {text}"
        );
        assert!(
            text.contains("keyb gr,,\\locale\\keyboard.sys"),
            "the keyb line names the keyboard and driver: {text}"
        );
        // MODE.COM and the EGA fonts land in LOCALE (payload ids 304
        // and 309-326 ride Destination::Locale), byte-identical to
        // their assets.
        for file in [FreeDosFile::ModeCom, FreeDosFile::Ega] {
            let want =
                std::fs::read(resources_dir().join(file.asset_file())).expect("the asset reads");
            let back = fat
                .read_file(&payload_dest(file))
                .expect("the locale file reads back");
            assert_eq!(
                back,
                want,
                "locale file {} is byte-identical to its asset",
                file.target_name()
            );
        }
        let listed = fat.list_dir("/").expect("the root lists");
        assert!(
            listed.iter().any(|entry| entry.short_name == "CONFIG.SYS"),
            "a non-US root carries CONFIG.SYS"
        );
        assert!(
            done.written()
                .iter()
                .any(|file| file.name() == "CONFIG.SYS"),
            "the report counts CONFIG.SYS as written"
        );
        assert!(
            done.written()
                .iter()
                .any(|file| file.name() == "AUTOEXEC.BAT"),
            "the report counts AUTOEXEC.BAT as written"
        );
    }

    #[test]
    fn second_install_keeps_everything() {
        // A second install over identical bytes keeps all 28 files
        // (the 27 payloads plus AUTOEXEC.BAT; the US plan has no
        // CONFIG.SYS): nothing writes, nothing refuses.
        let locale = Locale::us();
        let (_backing, mut fat) = formatted();
        let first = install_assets(&mut fat, &locale).expect("the first install runs");
        assert!(first.kept().is_empty(), "a fresh install keeps nothing");
        let again = install_assets(&mut fat, &locale).expect("identical bytes are kept");
        assert!(
            again.written().is_empty(),
            "nothing writes twice: {:?}",
            again.written()
        );
        assert_eq!(
            again.bytes_written(),
            0,
            "no byte written means a zero total"
        );
        let mut want: Vec<&str> = FreeDosFile::ALL
            .iter()
            .map(|file| file.target_name())
            .collect();
        want.push(AUTOEXEC_BAT);
        assert_eq!(
            again.kept(),
            want.as_slice(),
            "the second install keeps all 28 files in order"
        );
        assert!(
            again.record_written(),
            "the record rewrite still runs (it is unconditional)"
        );
        let want = std::fs::read(resources_dir().join(FreeDosFile::CommandCom.asset_file()))
            .expect("the asset reads");
        let back = fat
            .read_file("/COMMAND.COM")
            .expect("the kept file reads back");
        assert_eq!(back, want, "kept bytes unchanged");
    }

    #[test]
    fn differing_command_com_refuses() {
        // A foreign `/COMMAND.COM` refuses naming the file and stays
        // untouched — keeping it would boot a foreign shell.
        let (_backing, mut fat) = formatted();
        let foreign = b"foreign-command-bytes".to_vec();
        fat.create_file("/COMMAND.COM", foreign.len() as u64)
            .expect("a foreign file lands first");
        fat.write_at("/COMMAND.COM", 0, &foreign)
            .expect("the foreign write lands");
        let error = install_assets(&mut fat, &Locale::us()).expect_err("differing bytes refuse");
        let text = error.to_string();
        assert!(text.contains("COMMAND.COM"), "names the file: {text}");
        assert!(text.contains("differs"), "names the conflict: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let back = fat.read_file("/COMMAND.COM").expect("the file still reads");
        assert_eq!(back, foreign, "foreign bytes untouched");
    }

    #[test]
    fn differing_locale_ega_refuses() {
        // A foreign `/LOCALE/EGA.CPX` refuses naming the file and stays
        // untouched. The earlier payloads land first (id order), so the
        // refusal proves the sequence position, not just the policy.
        let (_backing, mut fat) = formatted();
        fat.mkdir("/LOCALE")
            .expect("the locale directory lands first");
        let foreign = b"foreign-ega-bytes".to_vec();
        fat.create_file("/LOCALE/EGA.CPX", foreign.len() as u64)
            .expect("a foreign file lands first");
        fat.write_at("/LOCALE/EGA.CPX", 0, &foreign)
            .expect("the foreign write lands");
        let error = install_assets(&mut fat, &Locale::us()).expect_err("differing bytes refuse");
        let text = error.to_string();
        assert!(text.contains("EGA.CPX"), "names the file: {text}");
        assert!(text.contains("differs"), "names the conflict: {text}");
        assert!(text.contains("/LOCALE"), "names the directory: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let back = fat
            .read_file("/LOCALE/EGA.CPX")
            .expect("the file still reads");
        assert_eq!(back, foreign, "foreign bytes untouched");
        let want = std::fs::read(resources_dir().join(FreeDosFile::CommandCom.asset_file()))
            .expect("the asset reads");
        let back = fat
            .read_file("/COMMAND.COM")
            .expect("the earlier payload reads back");
        assert_eq!(
            back, want,
            "the id-ordered payloads before the conflict landed"
        );
    }

    #[test]
    fn locale_file_refusal_leaves_the_boot_sector() {
        // Boot-record-last by construction: a refusal late in the
        // sequence (a differing AUTOEXEC.BAT, the last file before the
        // record) must leave sector 0 with the formatter's `EB 3C 90`,
        // not the FreeDOS head.
        let (backing, mut fat) = formatted();
        let foreign = b"foreign-autoexec-bytes".to_vec();
        fat.create_file("/AUTOEXEC.BAT", foreign.len() as u64)
            .expect("a foreign file lands first");
        fat.write_at("/AUTOEXEC.BAT", 0, &foreign)
            .expect("the foreign write lands");
        fat.flush().expect("the pre-install flush runs");
        let before = sector(&backing, 0);
        assert_eq!(
            &before[0..3],
            &[0xEB, 0x3C, 0x90],
            "the formatter's own jump"
        );
        let error =
            install_assets(&mut fat, &Locale::us()).expect_err("a differing AUTOEXEC.BAT refuses");
        let text = error.to_string();
        assert!(text.contains("AUTOEXEC.BAT"), "names the file: {text}");
        assert!(text.contains("differs"), "names the conflict: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        fat.flush().expect("the post-refusal flush runs");
        assert_eq!(
            sector(&backing, 0),
            before,
            "sector 0 still carries the formatter's record"
        );
        let back = fat
            .read_file("/AUTOEXEC.BAT")
            .expect("the file still reads");
        assert_eq!(back, foreign, "foreign bytes untouched");
    }

    #[test]
    fn locale_path_as_file_refuses() {
        // LOCALE as a plain file is not a directory to fill: the
        // install refuses naming it and writes nothing behind it.
        let (_backing, mut fat) = formatted();
        let foreign = b"a file, not a directory".to_vec();
        fat.create_file("/LOCALE", foreign.len() as u64)
            .expect("a file lands first");
        fat.write_at("/LOCALE", 0, &foreign)
            .expect("the file writes");
        let error = install_assets(&mut fat, &Locale::us()).expect_err("a file LOCALE refuses");
        let text = error.to_string();
        assert!(text.contains("LOCALE"), "names the path: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert!(
            fat.read_file("/COMMAND.COM").is_err(),
            "no payload landed behind the refusal"
        );
        let back = fat.read_file("/LOCALE").expect("the file still reads");
        assert_eq!(back, foreign, "foreign bytes untouched");
    }
}
