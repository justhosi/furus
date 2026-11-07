//! BCD store builder on top of a small in-crate `regf` editor (S21, slice 6 of 12).
//!
//! Question: after the image is applied, the USB needs boot entries
//! pointing at the applied Windows, a Boot Configuration Data store
//! on the ESP (UEFI) and on the data partition (BIOS), the way real
//! Rufus leaves them.
//!
//! What real Rufus does: it runs the *applied image's own* tools,
//! recovered from the decompiled `wue.c` (function `0x140066ea0`),
//! `bcdboot.exe /bootex /offline /f ALL /s <ESP>` followed by
//! `bcdedit.exe /store <ESP>\EFI\Microsoft\Boot\BCD /set {default}
//! recoveryenabled no`. On Linux that path needs Wine (about 500 MiB,
//! not installed on this host), so a host-side implementation is
//! needed, and this module is it.
//!
//! Evidence: the Windows 11 Enterprise Evaluation 24H2 ISO was mounted
//! read-only (`mount -t udf -o loop,ro`) and `sources/boot.wim` image 1
//! was extracted with `wimlib-imagex extract`. The image holds, among
//! others, `Windows/System32/config/BCD-Template` (20 480 bytes, a real
//! `regf` hive whose root key is `System` with an `Objects` key holding
//! 12 subkeys), its own `Windows/System32/bcdboot.exe` and
//! `bcdedit.exe`, the install-media stores `Windows/Boot/DVD/BCD`
//! (BIOS) and `Windows/Boot/EFI/BCD` (UEFI), and
//! `Windows/Boot/EFI/bootmgr.efi`.
//!
//! Candidates:
//! a. Write a store from scratch, rejected: the template already holds
//!    every object and element a boot needs except the two per-machine
//!    device elements, so generating a hive buys nothing.
//! b. Ship the applied image's own `BCD-Template` and patch it with a
//!    small in-crate `regf` editor, kept: minimal new code, no
//!    dependency, and the template locates Windows by path, so the
//!    patched store needs no GPT GUID and no MBR signature or offset,
//!    which also keeps a To Go store portable.
//! c. Run the image's `bcdboot`/`bcdedit` under Wine, rejected: Wine
//!    is heavy, needs the user's permission, is untested on this host,
//!    and PLAN calls it the last resort.
//!
//! Decision: candidate (b), implemented here. [`build`] copies the
//! template hive and patches it: the firmware-selected loader object
//! gets its `11000001`/`21000001` partition device elements plus
//! `12000002` (the winload path) and, when the caller names one, the
//! `12000004` edition description; `{bootmgr}` is repointed at that
//! loader (`23000003`, `24000001`, `24000010`); `{memdiag}` gets the
//! `11000001` boot device. No other bytes change except the header
//! checksum (and, when the template's own free space runs out, one
//! appended hive bin plus the header length that describes it, see
//! below).
//!
//! What slice 6 confirmed against a live template read (the slice-5
//! summary is superseded wherever it differs): every object is
//! `Objects\{guid}` with `Description` (one `Type` DWORD value) and
//! `Elements` subkeys; every element is an `Elements\{id}` subkey (the
//! id is 8 uppercase hex digits, for example `12000002`) holding a
//! single `Element` value whose type carries the encoding (`REG_SZ` 1,
//! `REG_BINARY` 3, `REG_MULTI_SZ` 7). The UEFI loader is
//! [`TEMPLATE_LOADER_B012`] (`42000002` =
//! `\system32\winload.efi`, no `42000003`, has `16000060`); the BIOS
//! loader is [`TEMPLATE_LOADER_A194`] (`42000002` =
//! `\system32\winload.exe`, no `16000060`, no `42000003`); the two PE
//! loaders ([`TEMPLATE_LOADER_7254`], [`TEMPLATE_LOADER_CBD9`]) carry
//! `42000003` = `\boot.wim` and are never picked. `{bootmgr}` carries
//! `12000002` = `\EFI\Microsoft\Boot\bootmgfw.efi`, the `23000003`
//! default object as a `REG_SZ` GUID string, `25000004` = 30 inline,
//! and no `24000001`/`24000010` yet. The real install-media stores
//! prove the encodings the template cannot show: `{bootmgr}` needs no
//! device element, `23000003` is a `REG_SZ`
//! GUID string, `24000001`/`24000010` are single-entry `REG_MULTI_SZ`
//! GUID lists, and `{memdiag}\11000001` is an 88-byte `REG_BINARY`
//! boot device. The BIOS install-media store carries no `12000002` on
//! `{bootmgr}` at all (the firmware default `\bootmgr` applies), so
//! this builder sets `{bootmgr}\12000002` explicitly to `\bootmgr`
//! for BIOS (a shorter string than the template's EFI path, so the
//! in-place shrink path is used) and keeps the template's
//! `\EFI\Microsoft\Boot\bootmgfw.efi` for UEFI; nothing is ever
//! deleted, so there is no delete primitive.
//!
//! Allocator and space: the editor allocates new cells from the hive's
//! own free cells first (first fit, splitting a larger free cell,
//! merging with free neighbours when freeing), grows a value or subkey
//! list in place when the cell right after it is free and large enough,
//! and otherwise moves the list to a bigger cell. The real 20 KiB
//! template has a single 472-byte free cell while a full store needs
//! about 1.4 KiB of new cells (six or seven element keys at 88-byte
//! `nk` plus value list, `vk` and data cells each, plus three regrown
//! subkey lists), so the free space alone cannot hold the store. When
//! it runs out the editor appends whole 4 KiB `hbin` pages (header
//! `hbin` with the same shape as the template's own, one free cell
//! covering the rest) and adds their size to the header length at
//! `0x28`, then recomputes the header checksum. The output stays a
//! plain valid hive: every free cell keeps a non-negative size,
//! allocated cells never overlap, and `hbin` sizes stay consistent. If
//! the template is truncated or otherwise too small to even parse,
//! [`build`] refuses with an [`CoreError::InvalidInput`] naming the
//! shortage in bytes.
//!
//! `regf` layout notes (verified byte-for-byte against the real
//! hives): all offsets below are relative to the 2-byte cell tag
//! (`nk`/`vk`/`lf`), which sits 4 bytes after the cell start (the
//! `i32` size comes first; negative means allocated). Key: flags
//! `u16` at `0x02` (name is latin-1 when `flags & 0x20`, else
//! UTF-16LE), parent at `0x10`, subkey count at `0x14`, subkey list at
//! `0x1C`, value count at `0x24`, value list at `0x28`, name length
//! `u16` at `0x48`, name at `0x4C`. Value: name length `u16` at `0x02`,
//! data size `u32` at `0x04` (bit `0x8000_0000` means the data lives
//! inline in the 4-byte field at `0x08`), data offset at `0x08`, type
//! `u32` at `0x0C`, flags `u16` at `0x10` (name is latin-1 when
//! `flags & 0x0001`), name at `0x14`. A value list body is an array of
//! `u32` `vk` offsets (`nval == 0` uses offset `0xFFFF_FFFF`).
//! Subkey lists: `lf`/`lh` hold a `u16` count at `0x02` then
//! (`u32` offset, `u32` hash) pairs; `li`/`ri` hold the count then bare
//! `u32` offsets. Every hash in the template is the first 4 name bytes
//! as little-endian `u32` (all 101 entries verify), so new entries use
//! exactly that convention. The header checksum at `0x1FC` is the XOR
//! of the 127 `u32` words at `0x00..=0x1FB`; the root cell offset is
//! the `u32` at `0x24` and the total hive-bin length the `u32` at
//! `0x28`.
//!
//! Naming honesty: object and element constants keep their slice-5
//! names (the committed record) with corrected roles where the live
//! read proved the old label wrong; [`ELEMENT_DISPLAY_ORDER`] stays
//! `0x14000006` but is documented as the inherited-objects list it
//! really is, while the boot-manager display order this builder writes
//! is [`ELEMENT_BOOT_DISPLAY_ORDER`] (`0x24000001`).
//!
//! Limitations, stated plainly: no Windows image has been booted yet
//! (the host has 7.6 GiB RAM with about 600 MiB free, so QEMU cannot
//! run Windows now); boot acceptance is slices 10-11. The template
//! above is from Windows 11 24H2; the Windows 10 template has not been
//! inspected, so [`build`] verifies the loader's `42000002` flavour
//! suffix and the `\windows` system root at build time and refuses
//! rather than patching a store it does not recognise.
//!
//! Not here yet: pipeline wiring.

use super::regf::*;
use crate::error::CoreError;
use crate::error::Result;

/// `{bootmgr}`: the boot manager object both stores patch.
pub const OBJECT_BOOTMGR: &str = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}";

/// `{memdiag}`: the memory-diagnostic object, which gains the boot device.
pub const OBJECT_MEMDIAG: &str = "{b2721d73-1db4-4c62-bf78-c548a880142d}";

/// `{globalsettings}`: global settings object, carried over untouched.
pub const OBJECT_GLOBAL_SETTINGS: &str = "{7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}";

/// `{bootloadersettings}`: loader-settings object, carried over untouched.
pub const OBJECT_BOOTLOADER_SETTINGS: &str = "{6efb52bf-1766-41db-a6b3-0ee5eff72bd7}";

/// `{hypervisorsettings}`: hypervisor-settings object, carried over untouched.
pub const OBJECT_HYPERVISOR_SETTINGS: &str = "{4636856e-540f-4170-a130-a84776f4c654}";

/// `{emssettings}`: EMS-settings object, carried over untouched.
pub const OBJECT_EMS_SETTINGS: &str = "{0ce4991b-e6b3-4b16-b23c-5e0d9250e5d9}";

/// `{legacy}`: the legacy (BIOS boot-sector) object, carried over untouched.
pub const OBJECT_LEGACY: &str = "{7ff607e0-4395-11db-b0de-0800200c9a66}";

/// Template-only minimal loader (`466f5a88-...`): carries only
/// `12000002` (`\ntldr`), `45000001` and `47000005`. Never picked: it
/// is not a winload loader (see the module docs).
pub const TEMPLATE_LOADER_466F: &str = "{466f5a88-0af2-4f76-9038-095b170dc21c}";

/// Template-only full loader (`7254a080-...`): a PE loader carrying
/// both `42000002` (`\system32\winload.efi`) and `42000003`
/// (`\boot.wim`). Never picked: the install-media path, not the
/// applied-image path.
pub const TEMPLATE_LOADER_7254: &str = "{7254a080-1510-4e85-ac0f-e7fb3d444736}";

/// The BIOS loader (`a1943bbc-...`): `42000002` =
/// `\system32\winload.exe`. [`build`] patches this object for
/// [`Firmware::Bios`] after confirming the `42000002` suffix live.
pub const TEMPLATE_LOADER_A194: &str = "{a1943bbc-ea85-487c-97c7-c9ede908a38a}";

/// The UEFI loader (`b012b84d-...`): `42000002` =
/// `\system32\winload.efi`. [`build`] patches this object for
/// [`Firmware::Uefi`] after confirming the `42000002` suffix live.
pub const TEMPLATE_LOADER_B012: &str = "{b012b84d-c47c-4ed5-b722-c0c42163e569}";

/// Template-only full loader (`cbd971bf-...`): a PE loader carrying
/// both `42000002` (`\system32\winload.exe`) and `42000003`
/// (`\boot.wim`), and the template's initial `{bootmgr}\23000003`
/// default. Never picked as the OS loader (it is the template's
/// placeholder default, repointed by [`build`]).
pub const TEMPLATE_LOADER_CBD9: &str = "{cbd971bf-b7b8-4885-951a-fa03044f5d71}";

/// `0x11000001` (class `0x11`, device): the boot-device element
/// `bcdboot` adds to `{bootmgr}` per machine; absent from the template.
/// [`build`] writes it on the chosen loader and on `{memdiag}` as an
/// 88-byte `REG_BINARY` partition or boot device (see
/// [`partition_device`] and [`boot_device`]).
pub const ELEMENT_DEVICE: u32 = 0x1100_0001;

/// `0x21000001` (class `0x21`, device): the os-device element `bcdboot`
/// adds to the chosen loader per machine; absent from the template.
/// [`build`] writes it as the same 88-byte partition device as
/// `0x11000001`.
pub const ELEMENT_OS_DEVICE: u32 = 0x2100_0001;

/// `0x22000002` (class `0x22`, string): the os device the template
/// loaders carry as a locate-by-path string (`REG_SZ` `\windows`).
/// [`build`] keeps the template value and refuses when it is missing
/// or different, since the written `12000002` hard-codes the
/// `\windows` prefix.
pub const ELEMENT_OS_LOCATE_PATH: u32 = 0x2200_0002;

/// `0x23000003` (class `0x23`): the default-object element on
/// `{bootmgr}` pointing at the chosen loader, a `REG_SZ` GUID string.
/// The template carries it (pointing at the placeholder loader);
/// [`build`] overwrites it in place and refuses a template that has
/// no such element to update.
pub const ELEMENT_DEFAULT_OBJECT: u32 = 0x2300_0003;

/// `0x24000001` (class `0x24`, GUID list): the boot-manager display
/// order on `{bootmgr}`, a single-entry `REG_MULTI_SZ` holding the
/// chosen loader. Absent from the template; [`build`] adds it.
pub const ELEMENT_BOOT_DISPLAY_ORDER: u32 = 0x2400_0001;

/// `0x24000010` (class `0x24`, GUID list): the tools display order on
/// `{bootmgr}`, a single-entry `REG_MULTI_SZ` holding `{memdiag}`.
/// Absent from the template; [`build`] adds it.
pub const ELEMENT_TOOLS_DISPLAY_ORDER: u32 = 0x2400_0010;

/// `0x12000002` (class `0x12`, string): the path element, the boot
/// application path on `{bootmgr}` and on
/// the minimal template loader. [`build`] adds it on the chosen
/// loader as the full winload path, sets it to `\bootmgr` on
/// `{bootmgr}` for [`Firmware::Bios`], and keeps the template's EFI
/// path on `{bootmgr}` for [`Firmware::Uefi`].
pub const ELEMENT_PATH: u32 = 0x1200_0002;

/// `0x12000004` (class `0x12`, string): the description element; [`build`]
/// sets it to the edition on the chosen loader when the request names
/// one.
pub const ELEMENT_DESCRIPTION: u32 = 0x1200_0004;

/// `0x12000005` (class `0x12`, string): the locale element.
pub const ELEMENT_LOCALE: u32 = 0x1200_0005;

/// `0x14000006` (class `0x14`, list): despite the constant name (kept
/// from the slice-5 record), the live template proves this is the
/// inherited-objects list (`BcdLibraryObjectList_InheritedObjects`), a
/// `REG_MULTI_SZ` of GUIDs carried by nearly every object. The
/// boot-manager display order is [`ELEMENT_BOOT_DISPLAY_ORDER`]
/// (`0x24000001`) instead. [`build`] never touches this element.
pub const ELEMENT_DISPLAY_ORDER: u32 = 0x1400_0006;

/// `0x25000004` (class `0x25`, integer): the timeout element on
/// `{bootmgr}`, carried over untouched.
pub const ELEMENT_TIMEOUT: u32 = 0x2500_0004;

/// `0x42000002` (class `0x42`, file path): the loader path element;
/// the template pairs it as `\system32\winload.efi` (UEFI loader) or
/// `\system32\winload.exe` (BIOS loader) next to `22000002` =
/// `\windows`. [`build`] confirms the flavour suffix live and keeps
/// the template value.
pub const ELEMENT_LOADER_PATH: u32 = 0x4200_0002;

/// `0x32000004` (class `0x32`, ramdisk options): the ramdisk path
/// element seen in the install-media stores `\boot\bcd` and
/// `\efi\microsoft\boot\bcd` extracted from `sources/boot.wim`, not in
/// `BCD-Template`.
pub const ELEMENT_RAMDISK_PATH: u32 = 0x3200_0004;

/// `0x31000003` (class `0x31`, device path): the device-path element
/// seen in the install-media stores `\boot\bcd` and
/// `\efi\microsoft\boot\bcd` extracted from `sources/boot.wim`, not in
/// `BCD-Template`.
pub const ELEMENT_DEVICE_PATH: u32 = 0x3100_0003;

/// `0x15000011` (class `0x15`, integer): carried by
/// `{hypervisorsettings}` as a one-byte integer (`04`); no finer role
/// observed.
pub const ELEMENT_15000011: u32 = 0x1500_0011;

/// `0x16000020` (class `0x16`, integer/boolean): carried by
/// `{emssettings}`; no finer role observed.
pub const ELEMENT_16000020: u32 = 0x1600_0020;

/// `0x16000060` (class `0x16`, integer/boolean): present on the UEFI
/// loader and some template loaders; no finer role observed.
pub const ELEMENT_16000060: u32 = 0x1600_0060;

/// `0x1600000B` (class `0x16`, integer/boolean): carried by
/// `{memdiag}`; no finer role observed.
pub const ELEMENT_1600000B: u32 = 0x1600_000B;

/// `0x17000077` (class `0x17`, integer/boolean): present on the full
/// template loaders; no finer role observed.
pub const ELEMENT_17000077: u32 = 0x1700_0077;

/// `0x25000020` (class `0x25`, integer): present on the full template
/// loaders; no finer role observed.
pub const ELEMENT_25000020: u32 = 0x2500_0020;

/// `0x26000022` (class `0x26`, boolean): present on the full template
/// loaders as a one-byte boolean (`01`); no finer role observed.
pub const ELEMENT_26000022: u32 = 0x2600_0022;

/// `0x45000001` (class `0x45`, `BcdSetupInteger_DeviceType`): the setup
/// device-type flag carried by nearly every object (one byte inline in
/// the template, `01` on `{bootmgr}` and `{memdiag}`, `02` on the
/// winload loaders); carried over untouched.
pub const ELEMENT_45000001: u32 = 0x4500_0001;

/// `0x47000005` (class `0x47`, binary): carried by nearly every
/// template object as a 16-byte blob (for example
/// `04000012000000000600000000000000`); no finer role observed.
pub const ELEMENT_47000005: u32 = 0x4700_0005;

/// `0x250000F3` (class `0x25`, integer): first `{legacy}` element; no
/// finer role observed.
pub const ELEMENT_250000F3: u32 = 0x2500_00F3;

/// `0x250000F4` (class `0x25`, integer): second `{legacy}` element; no
/// finer role observed.
pub const ELEMENT_250000F4: u32 = 0x2500_00F4;

/// `0x250000F5` (class `0x25`, integer): third `{legacy}` element; no
/// finer role observed.
pub const ELEMENT_250000F5: u32 = 0x2500_00F5;

/// Source path of the template inside an applied Windows image, with
/// forward slashes as it appears in the image tree.
pub const TEMPLATE_PATH: &str = "Windows/System32/config/BCD-Template";

/// Target store path on the ESP (backslashes as the firmware sees
/// them): the UEFI BCD the pipeline will write.
pub const UEFI_STORE_PATH: &str = "\\EFI\\Microsoft\\Boot\\BCD";

/// Target store path on the data partition (backslashes as the boot
/// manager sees them): the BIOS BCD the pipeline will write.
pub const BIOS_STORE_PATH: &str = "\\boot\\bcd";

/// The element class of `id`: the top byte (`id >> 24`).
///
/// The class is bits 28-31 (1 library, 2 application, 3 device,
/// 4 template) and the format is bits 24-27 (1 device, 2 string, 3 GUID,
/// 4 GUID list, 5 integer, 6 boolean, 7 integer list). The top nibble
/// alone cannot be the class: `0x11000001` (device) and `0x12000002`
/// (string) would collide at `0x1`, yet the template uses them for
/// different kinds. The full top byte keeps them apart, restated from
/// the value types the extracted template actually holds: `0x11`
/// device (added by `bcdboot`; absent from the template), `0x12`
/// string, `0x14` list, `0x15` integer (one byte observed),
/// `0x16` integer-or-boolean, `0x17` integer-or-boolean, `0x21` device
/// (added by `bcdboot`; absent from the template), `0x22` string
/// (observed `REG_SZ`), `0x23` default object (a `REG_SZ` GUID string
/// per the live read), `0x24` GUID list (observed `REG_MULTI_SZ`),
/// `0x25` integer, `0x26` boolean (one byte observed), `0x31` device
/// path and `0x32` ramdisk options (seen in the install-media stores,
/// not the template), `0x42` file path, `0x45` flags (`BcdSetupInteger_DeviceType`),
/// `0x47` binary (16 bytes observed).
#[must_use]
pub fn element_class(id: u32) -> u8 {
    // A shift, not an index: no failure mode, no panic path.
    (id >> 24) as u8
}

/// Which firmware path a store is for; selects the loader object and paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Firmware {
    /// UEFI: patch [`TEMPLATE_LOADER_B012`] (`\windows\system32\winload.efi`).
    Uefi,
    /// BIOS: patch [`TEMPLATE_LOADER_A194`] (`\windows\system32\winload.exe`).
    Bios,
}

/// The target disk identity, from the partition table the pipeline stamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceIdentity {
    /// GPT: raw 16-byte GUIDs as stored on disk (partition entry, then
    /// disk header), copied byte-for-byte into the device element.
    Gpt {
        /// Disk GUID, raw GPT header bytes.
        disk_guid: [u8; 16],
        /// Partition unique GUID, raw GPT entry bytes.
        partition_guid: [u8; 16],
    },
    /// MBR: the disk signature as stored at MBR offset `0x1B8`, plus
    /// the partition start in bytes.
    Mbr {
        /// Disk signature, byte order as stored in the MBR.
        disk_signature: [u8; 4],
        /// Partition start offset in bytes.
        partition_start_bytes: u64,
    },
}

/// What to build. `description` names the Windows edition if known.
#[derive(Debug, Clone, Copy)]
pub struct StoreRequest<'a> {
    /// Which firmware path the store is for.
    pub firmware: Firmware,
    /// The target disk identity the device elements encode.
    pub identity: DeviceIdentity,
    /// Edition description for the loader's `12000004`, when known.
    pub description: Option<&'a str>,
}

/// A built BCD store: the hive bytes plus what was written, for tests
/// and for the pipeline messages that will report the store.
#[derive(Debug, Clone)]
pub struct Store {
    /// The complete hive bytes, ready to write to the target.
    pub bytes: Vec<u8>,
    /// The firmware path the store was built for.
    pub firmware: Firmware,
    /// The loader object `{default}` points at (see [`default_object`]).
    pub default_guid: &'static str,
}

/// Which template object the store uses as `{default}`: the UEFI
/// loader for [`Firmware::Uefi`], the BIOS loader for
/// [`Firmware::Bios`].
#[must_use]
pub fn default_object(firmware: Firmware) -> &'static str {
    match firmware {
        Firmware::Uefi => TEMPLATE_LOADER_B012,
        Firmware::Bios => TEMPLATE_LOADER_A194,
    }
}

/// The winload path written as the loader's `12000002`, per firmware.
fn winload_full_path(firmware: Firmware) -> &'static str {
    match firmware {
        Firmware::Uefi => "\\windows\\system32\\winload.efi",
        Firmware::Bios => "\\windows\\system32\\winload.exe",
    }
}

/// The `42000002` value the chosen loader must already carry, per
/// firmware. [`build`] confirms it live before patching.
fn expected_loader_suffix(firmware: Firmware) -> &'static str {
    match firmware {
        Firmware::Uefi => "\\system32\\winload.efi",
        Firmware::Bios => "\\system32\\winload.exe",
    }
}

/// The 88-byte boot device element for `{memdiag}\11000001`
/// (`REG_BINARY`): 16 zero bytes, type 5 (`u32` at `0x10`), zero at
/// `0x14`, length `0x48` (`u32` at `0x18`), zeros after.
#[must_use]
pub fn boot_device() -> [u8; 88] {
    let mut device = [0u8; 88];
    imprint(&mut device, 0x10, &5u32.to_le_bytes());
    imprint(&mut device, 0x18, &0x48u32.to_le_bytes());
    device
}

/// The 88-byte partition device element for the loader's `11000001`
/// and `21000001` (`REG_BINARY`): 16 zero bytes, type 6 (`u32` at
/// `0x10`), zero at `0x14`, length `0x48` (`u32` at `0x18`), zero at
/// `0x1C`, then for MBR the partition start (`u64` at `0x20`), `1`
/// (`u32` at `0x34`) and the disk signature (4 bytes at `0x38`), and
/// for GPT the partition GUID (16 bytes at `0x20`), 8 zeros, and the
/// disk GUID (16 bytes at `0x38`).
#[must_use]
pub fn partition_device(identity: DeviceIdentity) -> [u8; 88] {
    let mut device = [0u8; 88];
    imprint(&mut device, 0x10, &6u32.to_le_bytes());
    imprint(&mut device, 0x18, &0x48u32.to_le_bytes());
    match identity {
        DeviceIdentity::Mbr {
            disk_signature,
            partition_start_bytes,
        } => {
            imprint(&mut device, 0x20, &partition_start_bytes.to_le_bytes());
            imprint(&mut device, 0x34, &1u32.to_le_bytes());
            imprint(&mut device, 0x38, &disk_signature);
        }
        DeviceIdentity::Gpt {
            disk_guid,
            partition_guid,
        } => {
            imprint(&mut device, 0x20, &partition_guid);
            imprint(&mut device, 0x38, &disk_guid);
        }
    }
    device
}

/// Build a complete BCD store from a template hive.
///
/// The template is the applied image's `Windows/System32/config/BCD-Template`
/// bytes. On success returns the patched hive bytes: the
/// firmware-selected loader (see [`default_object`]) gains
/// `11000001`/`21000001` partition devices, `12000002`, and the
/// edition description when given; `{bootmgr}` is repointed at it
/// (plus `\bootmgr` at its `12000002` for [`Firmware::Bios`});
/// `{memdiag}` gains the boot device; the header checksum is
/// recomputed. Refuses with [`CoreError::InvalidInput`] naming what is
/// wrong when the template is not a `regf` hive, is truncated, lacks
/// `System\Objects`, `{bootmgr}`, the required loader or
/// `{memdiag}`, or lacks an element the build has to update.
pub fn build(template: &[u8], request: &StoreRequest<'_>) -> Result<Vec<u8>> {
    Ok(build_store(template, request)?.bytes)
}

/// The [`build`] body, keeping the written metadata next to the bytes.
fn build_store(template: &[u8], request: &StoreRequest<'_>) -> Result<Store> {
    let firmware = request.firmware;
    let loader_guid = default_object(firmware);
    let firmware_name = match firmware {
        Firmware::Uefi => "UEFI",
        Firmware::Bios => "BIOS",
    };
    let mut hive = Hive::parse(template)?;
    let (root_name, _) = hive.nk_name(hive.root())?;
    if root_name != b"System" {
        return Err(CoreError::invalid(
            "bcd template root key is not System".to_string(),
        ));
    }
    let objects = hive
        .find_child(hive.root(), b"Objects")?
        .ok_or_else(|| CoreError::invalid("bcd template has no System\\Objects key"))?;
    let bootmgr = hive
        .find_child(objects, OBJECT_BOOTMGR.as_bytes())?
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd template is missing the boot manager object {OBJECT_BOOTMGR}"
            ))
        })?;
    let loader = hive
        .find_child(objects, loader_guid.as_bytes())?
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd template is missing the {firmware_name} loader object {loader_guid}"
            ))
        })?;
    let memdiag = hive
        .find_child(objects, OBJECT_MEMDIAG.as_bytes())?
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd template is missing the memory diagnostic object {OBJECT_MEMDIAG}"
            ))
        })?;
    let bootmgr_elements = hive.find_child(bootmgr, b"Elements")?.ok_or_else(|| {
        CoreError::invalid(format!(
            "bcd template object {OBJECT_BOOTMGR} has no Elements key"
        ))
    })?;
    let loader_elements = hive.find_child(loader, b"Elements")?.ok_or_else(|| {
        CoreError::invalid(format!(
            "bcd template loader {loader_guid} has no Elements key"
        ))
    })?;
    let memdiag_elements = hive.find_child(memdiag, b"Elements")?.ok_or_else(|| {
        CoreError::invalid(format!(
            "bcd template object {OBJECT_MEMDIAG} has no Elements key"
        ))
    })?;

    if hive
        .element_value(bootmgr_elements, ELEMENT_DEFAULT_OBJECT)?
        .is_none()
    {
        return Err(CoreError::invalid(format!(
            "bcd template object {OBJECT_BOOTMGR} has no 23000003 element to update"
        )));
    }
    match hive.element_value(loader_elements, ELEMENT_OS_LOCATE_PATH)? {
        Some((REG_SZ, data)) if decode_sz(&data)? == "\\windows" => {}
        Some(_) => {
            return Err(CoreError::invalid(format!(
                "bcd template loader {loader_guid} has no \\\\windows 22000002 system root to keep"
            )));
        }
        None => {
            return Err(CoreError::invalid(format!(
                "bcd template loader {loader_guid} has no 22000002 element to keep"
            )));
        }
    }
    let expected_suffix = expected_loader_suffix(firmware);
    match hive.element_value(loader_elements, ELEMENT_LOADER_PATH)? {
        Some((REG_SZ, data)) if decode_sz(&data)? == expected_suffix => {}
        Some((_, data)) => {
            let found = decode_sz(&data).unwrap_or_else(|_| "<not UTF-16>".to_string());
            return Err(CoreError::invalid(format!(
                "bcd template loader {loader_guid} carries 42000002 {found}, expected {expected_suffix}"
            )));
        }
        None => {
            return Err(CoreError::invalid(format!(
                "bcd template loader {loader_guid} has no 42000002 element to confirm"
            )));
        }
    }
    if hive
        .element_value(memdiag_elements, ELEMENT_PATH)?
        .is_none()
    {
        return Err(CoreError::invalid(format!(
            "bcd template object {OBJECT_MEMDIAG} has no 12000002 element to keep"
        )));
    }

    let partition = partition_device(request.identity);
    hive.set_element_sz(bootmgr_elements, ELEMENT_DEFAULT_OBJECT, loader_guid)?;
    hive.set_element_multisz(bootmgr_elements, ELEMENT_BOOT_DISPLAY_ORDER, &[loader_guid])?;
    hive.set_element_multisz(
        bootmgr_elements,
        ELEMENT_TOOLS_DISPLAY_ORDER,
        &[OBJECT_MEMDIAG],
    )?;
    if firmware == Firmware::Bios {
        hive.set_element_sz(bootmgr_elements, ELEMENT_PATH, "\\bootmgr")?;
    };
    hive.set_element_binary(loader_elements, ELEMENT_DEVICE, &partition)?;
    hive.set_element_binary(loader_elements, ELEMENT_OS_DEVICE, &partition)?;
    hive.set_element_sz(loader_elements, ELEMENT_PATH, winload_full_path(firmware))?;
    if let Some(description) = request.description {
        hive.set_element_sz(loader_elements, ELEMENT_DESCRIPTION, description)?;
    }
    hive.set_element_binary(memdiag_elements, ELEMENT_DEVICE, &boot_device())?;
    hive.update_checksum()?;
    Ok(Store {
        bytes: hive.into_bytes(),
        firmware,
        default_guid: loader_guid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// True when `text` has the well-known identifier shape:
    /// `{` + 8 + `-` + 4 + `-` + 4 + `-` + 4 + `-` + 12 lowercase hex
    /// digits + `}`. Hand-rolled (no regex crate in the tree).
    fn is_identifier_shape(text: &str) -> bool {
        const DASHES: [usize; 4] = [9, 14, 19, 24];
        const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
        let bytes = text.as_bytes();
        if bytes.len() != 38 || bytes[0] != b'{' || bytes[37] != b'}' {
            return false;
        }
        let mut group = 0usize;
        let mut width = 0usize;
        for (position, byte) in bytes.iter().enumerate().skip(1).take(36) {
            if DASHES.contains(&position) {
                if *byte != b'-' || width != GROUPS[group] {
                    return false;
                }
                group += 1;
                width = 0;
            } else {
                if !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase() {
                    return false;
                }
                width += 1;
            }
        }
        group == 4 && width == GROUPS[4]
    }

    #[test]
    fn element_ids_are_unique_and_classed() {
        // Every documented element id as a literal, pinned against its
        // constant plus the class the module docs promise: a typo or a
        // changed constant fails here instead of staying green.
        let table: [(u32, u32, u8); 26] = [
            (0x1100_0001, ELEMENT_DEVICE, 0x11),
            (0x1200_0002, ELEMENT_PATH, 0x12),
            (0x1200_0004, ELEMENT_DESCRIPTION, 0x12),
            (0x1200_0005, ELEMENT_LOCALE, 0x12),
            (0x1400_0006, ELEMENT_DISPLAY_ORDER, 0x14),
            (0x1500_0011, ELEMENT_15000011, 0x15),
            (0x1600_0020, ELEMENT_16000020, 0x16),
            (0x1600_0060, ELEMENT_16000060, 0x16),
            (0x1600_000B, ELEMENT_1600000B, 0x16),
            (0x1700_0077, ELEMENT_17000077, 0x17),
            (0x2100_0001, ELEMENT_OS_DEVICE, 0x21),
            (0x2200_0002, ELEMENT_OS_LOCATE_PATH, 0x22),
            (0x2300_0003, ELEMENT_DEFAULT_OBJECT, 0x23),
            (0x2400_0001, ELEMENT_BOOT_DISPLAY_ORDER, 0x24),
            (0x2400_0010, ELEMENT_TOOLS_DISPLAY_ORDER, 0x24),
            (0x2500_0004, ELEMENT_TIMEOUT, 0x25),
            (0x2500_0020, ELEMENT_25000020, 0x25),
            (0x2500_00F3, ELEMENT_250000F3, 0x25),
            (0x2500_00F4, ELEMENT_250000F4, 0x25),
            (0x2500_00F5, ELEMENT_250000F5, 0x25),
            (0x2600_0022, ELEMENT_26000022, 0x26),
            (0x3100_0003, ELEMENT_DEVICE_PATH, 0x31),
            (0x3200_0004, ELEMENT_RAMDISK_PATH, 0x32),
            (0x4200_0002, ELEMENT_LOADER_PATH, 0x42),
            (0x4500_0001, ELEMENT_45000001, 0x45),
            (0x4700_0005, ELEMENT_47000005, 0x47),
        ];
        let mut seen: Vec<u32> = Vec::new();
        for (literal, constant, class) in table {
            assert_eq!(
                literal, constant,
                "element constant must pin {literal:#010x}"
            );
            assert!(
                !seen.contains(&literal),
                "element id {literal:#010x} must appear exactly once"
            );
            seen.push(literal);
            assert_eq!(
                element_class(literal),
                class,
                "element id {literal:#010x} must class as {class:#04x}"
            );
        }
        // Spot checks that the top byte (not the nibble) decides:
        // 0x11 device and 0x12 string share nibble 0x1 but class apart.
        assert_eq!(element_class(0x1100_0001), 0x11);
        assert_eq!(element_class(0x1200_0002), 0x12);
    }

    #[test]
    fn well_known_identifiers_are_distinct_and_shaped() {
        let known = [
            OBJECT_BOOTMGR,
            OBJECT_MEMDIAG,
            OBJECT_GLOBAL_SETTINGS,
            OBJECT_BOOTLOADER_SETTINGS,
            OBJECT_HYPERVISOR_SETTINGS,
            OBJECT_EMS_SETTINGS,
            OBJECT_LEGACY,
        ];
        assert!(
            is_identifier_shape("{9dea862c-5cdd-4e70-acc1-f32b344d4795}"),
            "the validator must accept a known-good identifier"
        );
        assert!(
            !is_identifier_shape("9dea862c-5cdd-4e70-acc1-f32b344d4795"),
            "missing braces must not validate"
        );
        assert!(
            !is_identifier_shape("{9DEA862C-5CDD-4E70-ACC1-F32B344D4795}"),
            "uppercase hex must not validate"
        );
        assert!(
            !is_identifier_shape("{9dea862c-5cdd-4e70-acc1-f32b344d479}"),
            "a short tail must not validate"
        );
        let mut seen: Vec<&str> = Vec::new();
        for identifier in known {
            assert!(
                is_identifier_shape(identifier),
                "well-known identifier {identifier} must have the canonical shape"
            );
            assert!(
                !seen.contains(&identifier),
                "well-known identifier {identifier} must be distinct"
            );
            seen.push(identifier);
        }
    }

    #[test]
    fn identifier_constants_pin_their_literals() {
        // Every object identifier as a literal: a typo or a changed
        // constant fails here, so the suite pins values, not names.
        assert_eq!(OBJECT_BOOTMGR, "{9dea862c-5cdd-4e70-acc1-f32b344d4795}");
        assert_eq!(OBJECT_MEMDIAG, "{b2721d73-1db4-4c62-bf78-c548a880142d}");
        assert_eq!(
            OBJECT_GLOBAL_SETTINGS,
            "{7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}"
        );
        assert_eq!(
            OBJECT_BOOTLOADER_SETTINGS,
            "{6efb52bf-1766-41db-a6b3-0ee5eff72bd7}"
        );
        assert_eq!(
            OBJECT_HYPERVISOR_SETTINGS,
            "{4636856e-540f-4170-a130-a84776f4c654}"
        );
        assert_eq!(
            OBJECT_EMS_SETTINGS,
            "{0ce4991b-e6b3-4b16-b23c-5e0d9250e5d9}"
        );
        assert_eq!(OBJECT_LEGACY, "{7ff607e0-4395-11db-b0de-0800200c9a66}");
        assert_eq!(
            TEMPLATE_LOADER_466F,
            "{466f5a88-0af2-4f76-9038-095b170dc21c}"
        );
        assert_eq!(
            TEMPLATE_LOADER_7254,
            "{7254a080-1510-4e85-ac0f-e7fb3d444736}"
        );
        assert_eq!(
            TEMPLATE_LOADER_A194,
            "{a1943bbc-ea85-487c-97c7-c9ede908a38a}"
        );
        assert_eq!(
            TEMPLATE_LOADER_B012,
            "{b012b84d-c47c-4ed5-b722-c0c42163e569}"
        );
        assert_eq!(
            TEMPLATE_LOADER_CBD9,
            "{cbd971bf-b7b8-4885-951a-fa03044f5d71}"
        );
    }

    #[test]
    fn bootmgr_guid_bytes_render_as_the_bootmgr_identifier() {
        // The on-disk little-endian bytes of {bootmgr} through the
        // shared mixed-endian formatter must equal the constant the
        // builder patches against.
        let raw: [u8; 16] = [
            0x2c, 0x86, 0xea, 0x9d, 0xdd, 0x5c, 0x70, 0x4e, 0xac, 0xc1, 0xf3, 0x2b, 0x34, 0x4d,
            0x47, 0x95,
        ];
        let rendered = crate::part::gpt::guid_to_string(&raw);
        assert_eq!(
            rendered, "9dea862c-5cdd-4e70-acc1-f32b344d4795",
            "the mixed-endian groups must decode first"
        );
        assert_eq!(
            OBJECT_BOOTMGR, "{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
            "the bootmgr constant must brace the rendered bytes"
        );
    }

    #[test]
    fn template_and_store_paths_are_ascii_with_documented_roots() {
        for path in [TEMPLATE_PATH, UEFI_STORE_PATH, BIOS_STORE_PATH] {
            assert!(
                path.is_ascii(),
                "bcd path {path} must stay plain ASCII for byte-level patching"
            );
        }
        assert!(
            TEMPLATE_PATH.starts_with("Windows/"),
            "template path must hang off the image Windows dir"
        );
        assert!(
            TEMPLATE_PATH.ends_with("BCD-Template"),
            "template path must name the BCD-Template hive"
        );
        assert!(
            UEFI_STORE_PATH.starts_with("\\EFI"),
            "the UEFI store must live under EFI on the ESP"
        );
        assert!(
            BIOS_STORE_PATH.starts_with("\\boot"),
            "the BIOS store must live under boot on the data partition"
        );
    }

    #[test]
    fn default_object_selects_the_winload_loader_per_firmware() {
        assert_eq!(default_object(Firmware::Uefi), TEMPLATE_LOADER_B012);
        assert_eq!(default_object(Firmware::Bios), TEMPLATE_LOADER_A194);
        assert_eq!(
            default_object(Firmware::Uefi),
            "{b012b84d-c47c-4ed5-b722-c0c42163e569}"
        );
        assert_eq!(
            default_object(Firmware::Bios),
            "{a1943bbc-ea85-487c-97c7-c9ede908a38a}"
        );
    }

    #[test]
    fn element_names_render_as_uppercase_hex() {
        assert_eq!(element_name(0x1100_0001), *b"11000001");
        assert_eq!(element_name(0x2400_0001), *b"24000001");
        assert_eq!(element_name(0x2400_0010), *b"24000010");
        assert_eq!(element_name(0x2500_00F3), *b"250000F3");
        assert_eq!(element_name(0x1600_000B), *b"1600000B");
    }

    #[test]
    fn boot_device_is_the_88_byte_no_disk_device() {
        let device = boot_device();
        assert_eq!(device.len(), 88);
        assert_eq!(device[0x00..0x10], [0u8; 16]);
        assert_eq!(device[0x10..0x14], [5u8, 0, 0, 0]);
        assert_eq!(device[0x14..0x18], [0u8; 4]);
        assert_eq!(device[0x18..0x1C], [0x48u8, 0, 0, 0]);
        assert_eq!(device[0x1C..0x58], [0u8; 0x58 - 0x1C]);
    }

    #[test]
    fn partition_device_encodes_mbr_identity() {
        let device = partition_device(DeviceIdentity::Mbr {
            disk_signature: [0x78, 0x56, 0x34, 0x12],
            partition_start_bytes: 0x0010_0000,
        });
        assert_eq!(device.len(), 88);
        assert_eq!(device[0x00..0x10], [0u8; 16]);
        assert_eq!(device[0x10..0x14], [6u8, 0, 0, 0]);
        assert_eq!(device[0x14..0x18], [0u8; 4]);
        assert_eq!(device[0x18..0x1C], [0x48u8, 0, 0, 0]);
        assert_eq!(device[0x1C..0x20], [0u8; 4]);
        assert_eq!(
            device[0x20..0x28],
            [0x00u8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(device[0x28..0x34], [0u8; 12]);
        assert_eq!(device[0x34..0x38], [1u8, 0, 0, 0]);
        assert_eq!(device[0x38..0x3C], [0x78u8, 0x56, 0x34, 0x12]);
        assert_eq!(device[0x3C..0x58], [0u8; 0x58 - 0x3C]);
    }

    #[test]
    fn partition_device_encodes_gpt_identity() {
        let partition_guid = [
            0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        let disk_guid = [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let device = partition_device(DeviceIdentity::Gpt {
            disk_guid,
            partition_guid,
        });
        assert_eq!(device.len(), 88);
        assert_eq!(device[0x00..0x10], [0u8; 16]);
        assert_eq!(device[0x10..0x14], [6u8, 0, 0, 0]);
        assert_eq!(device[0x14..0x18], [0u8; 4]);
        assert_eq!(device[0x18..0x1C], [0x48u8, 0, 0, 0]);
        assert_eq!(device[0x1C..0x20], [0u8; 4]);
        assert_eq!(device[0x20..0x30], partition_guid);
        assert_eq!(device[0x30..0x38], [0u8; 8]);
        assert_eq!(device[0x38..0x48], disk_guid);
        assert_eq!(device[0x48..0x58], [0u8; 0x58 - 0x48]);
    }

    // -- Test-only hive construction -------------------------------------
    //
    // The fixtures below are hand-built minimal hives (no Microsoft
    // bytes): a bare header plus one bin with a `System` root, extended
    // through the production editor itself, so the tests exercise the
    // same allocation paths as a real build.

    /// Start a minimal hive: header plus two bins holding a `System`
    /// root key and free space, so the fixture and the stores built
    /// from it fit without appending bins.
    fn empty_hive() -> Hive {
        let mut buf = vec![0u8; 0x200];
        buf[0..4].copy_from_slice(b"regf");
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        buf[8..12].copy_from_slice(&1u32.to_le_bytes());
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        buf[0x18..0x1C].copy_from_slice(&3u32.to_le_bytes());
        buf[HDR_ROOT..HDR_ROOT + 4].copy_from_slice(&0x20u32.to_le_bytes());
        buf[HDR_BIN_LENGTH..HDR_BIN_LENGTH + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        buf.resize(0x3000, 0);
        buf[0x1000..0x1004].copy_from_slice(b"hbin");
        buf[0x1004..0x1008].copy_from_slice(&0u32.to_le_bytes());
        buf[0x1008..0x100C].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[0x2000..0x2004].copy_from_slice(b"hbin");
        buf[0x2004..0x2008].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[0x2008..0x200C].copy_from_slice(&0x1000u32.to_le_bytes());
        // Root `System` key at cell 0x20: 4 + 0x4C + 6 = 86, rounded 88.
        let root_file = 0x1020usize;
        buf[root_file..root_file + 4].copy_from_slice(&(-88i32).to_le_bytes());
        buf[root_file + 4..root_file + 6].copy_from_slice(b"nk");
        buf[root_file + 6..root_file + 8].copy_from_slice(&0x20u16.to_le_bytes());
        buf[root_file + 0x14..root_file + 0x18].copy_from_slice(&NONE.to_le_bytes());
        buf[root_file + 0x20..root_file + 0x24].copy_from_slice(&NONE.to_le_bytes());
        buf[root_file + 0x2C..root_file + 0x30].copy_from_slice(&NONE.to_le_bytes());
        buf[root_file + 0x34..root_file + 0x38].copy_from_slice(&NONE.to_le_bytes());
        buf[root_file + 0x4C..root_file + 0x4E].copy_from_slice(&6u16.to_le_bytes());
        buf[root_file + 0x50..root_file + 0x56].copy_from_slice(b"System");
        // Free cell covering the rest of the first bin.
        let free_file = root_file + 88;
        let free_size = 0x1000u32 - 0x20 - 88;
        buf[free_file..free_file + 4].copy_from_slice(&(free_size as i32).to_le_bytes());
        // Second bin stays one free cell.
        let free2 = 0x2020usize;
        buf[free2..free2 + 4].copy_from_slice(&(HBIN_USABLE as i32).to_le_bytes());
        let checksum = Hive::header_checksum(&buf).expect("fixture header must checksum");
        buf[HDR_CHECKSUM..HDR_CHECKSUM + 4].copy_from_slice(&checksum.to_le_bytes());
        Hive::parse(&buf).expect("hand-built fixture must parse")
    }

    /// Add a subkey and return its cell offset.
    fn add_key(hive: &mut Hive, parent: usize, name: &[u8]) -> usize {
        hive.add_child_key(parent, name, None)
            .expect("fixture key must allocate")
    }

    /// Add an `Elements\{id}` subkey plus its `Element` value.
    fn add_element(hive: &mut Hive, elements: usize, id: &str, vtype: u32, data: &[u8]) {
        let key = add_key(hive, elements, id.as_bytes());
        hive.add_value(key, b"Element", vtype, data)
            .expect("fixture element must allocate");
    }

    /// Build a template-shaped fixture: `System\Objects` with
    /// `{bootmgr}`, both winload loaders and `{memdiag}`, each with an
    /// `Elements` key holding the elements [`build`] reads.
    fn template_fixture() -> Vec<u8> {
        let mut hive = empty_hive();
        let root = hive.root();
        let objects = add_key(&mut hive, root, b"Objects");
        let bootmgr = add_key(&mut hive, objects, OBJECT_BOOTMGR.as_bytes());
        let uefi = add_key(&mut hive, objects, TEMPLATE_LOADER_B012.as_bytes());
        let bios = add_key(&mut hive, objects, TEMPLATE_LOADER_A194.as_bytes());
        let memdiag = add_key(&mut hive, objects, OBJECT_MEMDIAG.as_bytes());

        let bootmgr_el = add_key(&mut hive, bootmgr, b"Elements");
        add_element(
            &mut hive,
            bootmgr_el,
            "23000003",
            REG_SZ,
            &utf16_nul(TEMPLATE_LOADER_CBD9),
        );
        add_element(
            &mut hive,
            bootmgr_el,
            "12000002",
            REG_SZ,
            &utf16_nul("\\EFI\\Microsoft\\Boot\\bootmgfw.efi"),
        );
        add_element(&mut hive, bootmgr_el, "25000004", REG_BINARY, &[0x1e]);

        for (loader, suffix) in [
            (uefi, "\\system32\\winload.efi"),
            (bios, "\\system32\\winload.exe"),
        ] {
            let elements = add_key(&mut hive, loader, b"Elements");
            add_element(
                &mut hive,
                elements,
                "22000002",
                REG_SZ,
                &utf16_nul("\\windows"),
            );
            add_element(&mut hive, elements, "42000002", REG_SZ, &utf16_nul(suffix));
        }

        let memdiag_el = add_key(&mut hive, memdiag, b"Elements");
        add_element(
            &mut hive,
            memdiag_el,
            "12000002",
            REG_SZ,
            &utf16_nul("\\boot\\memtest.exe"),
        );
        add_element(
            &mut hive,
            memdiag_el,
            "12000005",
            REG_SZ,
            &utf16_nul("en-US"),
        );

        hive.update_checksum().expect("fixture checksum must store");
        hive.into_bytes()
    }

    /// Walk every bin and cell, asserting sizes tile exactly, free
    /// cells stay valid, allocated cells never overlap, and every
    /// `lf`/`lh` entry hash matches the first-4-bytes convention.
    fn assert_tiling(bytes: &[u8]) {
        assert!(bytes.len() >= BIN_BASE + HBIN_HEAD);
        assert_eq!(bytes.len() % BIN_SIZE, 0);
        let mut bin = BIN_BASE;
        while bin < bytes.len() {
            assert_eq!(
                &bytes[bin..bin + 4],
                b"hbin",
                "bin at {bin:#x} must keep magic"
            );
            let size =
                i32::from_le_bytes(bytes[bin + 8..bin + 12].try_into().expect("bin size")) as usize;
            let bin_end = bin + size;
            let mut cur = bin + HBIN_HEAD;
            while cur < bin_end {
                let raw = i32::from_le_bytes(bytes[cur..cur + 4].try_into().expect("size"));
                assert_ne!(raw, 0, "zero-size cell at {cur:#x}");
                let cap = raw.unsigned_abs() as usize;
                assert!(cap >= MIN_CELL && cap.is_multiple_of(CELL_ROUND));
                if bytes[cur + 4..cur + 6] == *b"lf" || bytes[cur + 4..cur + 6] == *b"lh" {
                    let count =
                        u16::from_le_bytes(bytes[cur + 6..cur + 8].try_into().expect("count"))
                            as usize;
                    for index in 0..count {
                        let at = cur + 4 + LIST_ENTRIES + index * 8;
                        let child = u32::from_le_bytes(bytes[at..at + 4].try_into().expect("entry"))
                            as usize;
                        let stored =
                            u32::from_le_bytes(bytes[at + 4..at + 8].try_into().expect("hash"));
                        let file = child + CELL_BASE;
                        assert_eq!(&bytes[file + 4..file + 6], b"nk");
                        let latin1 = u16::from_le_bytes(
                            bytes[file + 6..file + 8].try_into().expect("flags"),
                        ) & NK_COMPRESSED
                            != 0;
                        let len = u16::from_le_bytes(
                            bytes[file + 4 + NK_NAMELEN..file + 4 + NK_NAMELEN + 2]
                                .try_into()
                                .expect("namelen"),
                        ) as usize;
                        let name = &bytes[file + 4 + NK_NAME..file + 4 + NK_NAME + len];
                        assert_eq!(stored, lf_hash(name), "hash at {at:#x} must be first-4");
                        assert!(latin1, "fixture keys stay latin-1");
                    }
                }
                cur += cap;
            }
            assert_eq!(cur, bin_end);
            bin = bin_end;
        }
        // Checksum must verify, which is also what Hive::parse enforces.
        let stored = u32::from_le_bytes(
            bytes[HDR_CHECKSUM..HDR_CHECKSUM + 4]
                .try_into()
                .expect("checksum"),
        );
        assert_eq!(Hive::header_checksum(bytes), Some(stored));
    }

    /// Total free bytes across all bins.
    fn free_bytes(bytes: &[u8]) -> usize {
        let mut total = 0;
        let mut bin = BIN_BASE;
        while bin < bytes.len() {
            let size =
                i32::from_le_bytes(bytes[bin + 8..bin + 12].try_into().expect("bin")) as usize;
            let mut cur = bin + HBIN_HEAD;
            while cur < bin + size {
                let raw = i32::from_le_bytes(bytes[cur..cur + 4].try_into().expect("cell"));
                if raw > 0 {
                    total += raw as usize;
                }
                cur += raw.unsigned_abs() as usize;
            }
            bin += size;
        }
        total
    }

    #[test]
    fn values_round_trip_through_add_shrink_and_grow() {
        let mut hive = empty_hive();
        let root = hive.root();
        let child = add_key(&mut hive, root, b"Child");
        assert_tiling(&hive.buf);

        // Add a 100-byte binary value: new data cell, new vk, list grows
        // from zero to one entry.
        let big: Vec<u8> = (0..100u32).map(|n| (n & 0xFF) as u8).collect();
        hive.add_value(root, b"Big", REG_BINARY, &big)
            .expect("add must allocate");
        let (vtype, data) = hive
            .value_data(
                hive.find_value(root, b"Big")
                    .expect("find")
                    .expect("present"),
            )
            .expect("read");
        assert_eq!((vtype, data), (REG_BINARY, big));
        hive.update_checksum().expect("checksum");
        assert_tiling(&hive.buf);

        // Shrink to 2 bytes: goes inline, frees the 100-byte data cell.
        let before = free_bytes(&hive.buf);
        let vk_before = hive
            .find_value(root, b"Big")
            .expect("find")
            .expect("present");
        hive.set_value_data(vk_before, REG_BINARY, &[0xAA, 0xBB])
            .expect("shrink must go inline");
        let vk_after = hive
            .find_value(root, b"Big")
            .expect("find")
            .expect("present");
        assert_eq!(
            vk_before, vk_after,
            "shrinking in place must keep the value cell offset"
        );
        let raw_size = hive.vk_u32(vk_after, 0x04, "test").expect("size");
        assert_ne!(
            raw_size & INLINE_FLAG,
            0,
            "a 2-byte value must use the inline form"
        );
        let (vtype, data) = hive
            .value_data(
                hive.find_value(root, b"Big")
                    .expect("find")
                    .expect("present"),
            )
            .expect("read");
        assert_eq!((vtype, data), (REG_BINARY, vec![0xAA, 0xBB]));
        assert!(
            free_bytes(&hive.buf) > before,
            "shrinking to inline must release the data cell"
        );
        hive.update_checksum().expect("checksum");
        assert_tiling(&hive.buf);

        // Grow to 50 bytes: leaves inline for a fresh data cell. The
        // value cell itself is reused; only the data relocates.
        let grown: Vec<u8> = (0..50u32).map(|n| (n ^ 0x5A & 0xFF) as u8).collect();
        hive.set_value_data(vk_after, REG_SZ, &grown)
            .expect("grow must allocate");
        let vk_grown = hive
            .find_value(root, b"Big")
            .expect("find")
            .expect("present");
        assert_eq!(
            vk_grown, vk_after,
            "growing must reuse the value cell and update its data pointer"
        );
        let (vtype, data) = hive.value_data(vk_grown).expect("read");
        assert_eq!((vtype, data), (REG_SZ, grown));
        hive.update_checksum().expect("checksum");
        assert_tiling(&hive.buf);

        // Exactly 4 bytes still fits the inline form (checked on the
        // child key so the root value-list assertions below stay exact).
        hive.add_value(child, b"Four", REG_BINARY, &[1, 2, 3, 4])
            .expect("4-byte add must allocate");
        let vk_four = hive
            .find_value(child, b"Four")
            .expect("find")
            .expect("present");
        let four_size = hive.vk_u32(vk_four, 0x04, "test").expect("size");
        assert_ne!(
            four_size & INLINE_FLAG,
            0,
            "a 4-byte value must use the inline form"
        );
        let (vtype, data) = hive.value_data(vk_four).expect("read");
        assert_eq!((vtype, data), (REG_BINARY, vec![1, 2, 3, 4]));
        hive.update_checksum().expect("checksum");
        assert_tiling(&hive.buf);

        // A second value on the same key exercises value-list growth.
        // Whether the list grows in place or relocates depends on the
        // neighbour cell, so the test pins correctness, not placement:
        // both entries survive, the count updates, and the hive still
        // tiles.
        hive.add_value(child, b"Other", REG_SZ, &utf16_nul("hi"))
            .expect("add on child");
        hive.add_value(root, b"Second", REG_BINARY, &[1, 2, 3])
            .expect("second add");
        assert_eq!(
            hive.nk_u32(root, 0x24, "value count").expect("vlist count"),
            2,
            "root must count both values after list growth"
        );
        let names = hive
            .value_list(root)
            .expect("values")
            .into_iter()
            .map(|vk| {
                let file = Hive::cell_file(vk, "test").expect("file");
                let len = hive.read_u16(file + 4 + 0x02, "test").expect("len") as usize;
                hive.buf[file + 4 + VK_FIXED..file + 4 + VK_FIXED + len].to_vec()
            })
            .collect::<Vec<_>>();
        assert_eq!(names, vec![b"Big".to_vec(), b"Second".to_vec()]);
        hive.update_checksum().expect("checksum");
        assert_tiling(&hive.buf);

        // Adding an existing value refuses instead of duplicating.
        let err = hive
            .add_value(root, b"Big", REG_BINARY, &[9])
            .expect_err("duplicate add must refuse");
        assert!(err.to_string().contains("already has a value"));
    }

    #[test]
    fn value_list_grows_in_place_when_the_neighbour_is_free() {
        // A value list that is the last cell in the bin has free space
        // right after it, so growing it must reuse the cell instead of
        // relocating it. (`add_value` allocates the new value first, so
        // it usually relocates; this pins the in-place path directly.)
        let mut hive = empty_hive();
        let root = hive.root();
        let fresh = add_key(&mut hive, root, b"Fresh");
        hive.add_value(fresh, b"First", REG_BINARY, &[1])
            .expect("first add must allocate");
        let list = hive.nk_u32(fresh, 0x28, "value list").expect("vlist");
        let file = Hive::cell_file(list as usize, "test").expect("file");
        let old_raw = hive.read_i32(file, "test").expect("size");
        let old_total = old_raw.unsigned_abs() as usize;
        let new_total = Hive::cell_total(8).expect("total");
        assert!(
            hive.try_grow_in_place(file, old_total, new_total)
                .expect("grow must not fail"),
            "growing into a free neighbour must happen in place"
        );
        assert_eq!(
            hive.nk_u32(fresh, 0x28, "value list").expect("vlist"),
            list,
            "the list cell offset must not move"
        );
        hive.update_checksum().expect("checksum");
        assert_tiling(&hive.buf);
    }

    #[test]
    fn synthetic_template_builds_uefi_and_bios_stores() {
        let gpt = DeviceIdentity::Gpt {
            disk_guid: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ],
            partition_guid: [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                0xFF, 0x00,
            ],
        };
        let mbr = DeviceIdentity::Mbr {
            disk_signature: [0x78, 0x56, 0x34, 0x12],
            partition_start_bytes: 0x0010_0000,
        };
        for (firmware, identity, description) in [
            (Firmware::Uefi, gpt, Some("Windows 11 Pro")),
            (Firmware::Bios, mbr, None),
            (Firmware::Uefi, mbr, Some("X")),
            (Firmware::Bios, gpt, Some("Windows 11 Enterprise")),
        ] {
            let template = template_fixture();
            let request = StoreRequest {
                firmware,
                identity,
                description,
            };
            let out = build(&template, &request).expect("synthetic build must succeed");
            assert_tiling(&out);
            assert_eq!(
                out.len(),
                template.len(),
                "a synthetic build must fit the fixture free space without growing the file"
            );
            // Re-parsing verifies the checksum, like the pipeline will.
            let hive = Hive::parse(&out).expect("output must re-parse");
            let loader = default_object(firmware);

            let (vtype, data) = hive
                .element_data(OBJECT_BOOTMGR, ELEMENT_DEFAULT_OBJECT)
                .expect("read default")
                .expect("23000003 must exist");
            assert_eq!(vtype, REG_SZ);
            assert_eq!(decode_sz(&data).expect("guid text"), loader);

            let (vtype, data) = hive
                .element_data(OBJECT_BOOTMGR, ELEMENT_BOOT_DISPLAY_ORDER)
                .expect("read display order")
                .expect("24000001 must exist");
            assert_eq!(vtype, REG_MULTI_SZ);
            assert_eq!(
                decode_multisz(&data).expect("guid list"),
                vec![loader.to_string()]
            );

            let (vtype, data) = hive
                .element_data(OBJECT_BOOTMGR, ELEMENT_TOOLS_DISPLAY_ORDER)
                .expect("read tools order")
                .expect("24000010 must exist");
            assert_eq!(vtype, REG_MULTI_SZ);
            assert_eq!(
                decode_multisz(&data).expect("guid list"),
                vec![OBJECT_MEMDIAG.to_string()]
            );

            let expected_device = partition_device(identity);
            for element in [ELEMENT_DEVICE, ELEMENT_OS_DEVICE] {
                let (vtype, data) = hive
                    .element_data(loader, element)
                    .expect("read device")
                    .expect("loader device must exist");
                assert_eq!(vtype, REG_BINARY);
                assert_eq!(data, expected_device.to_vec());
            }
            let (vtype, data) = hive
                .element_data(loader, ELEMENT_PATH)
                .expect("read path")
                .expect("12000002 must exist");
            assert_eq!(vtype, REG_SZ);
            assert_eq!(
                decode_sz(&data).expect("path text"),
                winload_full_path(firmware)
            );
            match description {
                Some(text) => {
                    let (vtype, data) = hive
                        .element_data(loader, ELEMENT_DESCRIPTION)
                        .expect("read description")
                        .expect("12000004 must exist when given");
                    assert_eq!(vtype, REG_SZ);
                    assert_eq!(decode_sz(&data).expect("description text"), text);
                }
                None => assert!(
                    hive.element_data(loader, ELEMENT_DESCRIPTION)
                        .expect("read description")
                        .is_none(),
                    "no description means no 12000004 element"
                ),
            }

            let (vtype, data) = hive
                .element_data(loader, ELEMENT_OS_LOCATE_PATH)
                .expect("read system root")
                .expect("22000002 must survive");
            assert_eq!(vtype, REG_SZ);
            assert_eq!(decode_sz(&data).expect("root text"), "\\windows");

            // The boot-manager application path is per firmware:
            // BIOS points at the firmware default, UEFI keeps the
            // template's EFI loader path.
            let (vtype, data) = hive
                .element_data(OBJECT_BOOTMGR, ELEMENT_PATH)
                .expect("read bootmgr path")
                .expect("bootmgr 12000002 must survive");
            assert_eq!(vtype, REG_SZ);
            let expected_bootmgr_path = match firmware {
                Firmware::Bios => "\\bootmgr",
                Firmware::Uefi => "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
            };
            assert_eq!(decode_sz(&data).expect("path text"), expected_bootmgr_path);
            // Untouched values survive byte-for-byte.
            let (vtype, data) = hive
                .element_data(OBJECT_BOOTMGR, 0x2500_0004)
                .expect("read timeout")
                .expect("timeout must survive");
            assert_eq!((vtype, data), (REG_BINARY, vec![0x1e]));

            let (vtype, data) = hive
                .element_data(OBJECT_MEMDIAG, ELEMENT_DEVICE)
                .expect("read memdiag device")
                .expect("memdiag 11000001 must exist");
            assert_eq!(vtype, REG_BINARY);
            assert_eq!(data, boot_device().to_vec());
        }
    }

    #[test]
    fn refusals_name_what_is_wrong() {
        let gpt = DeviceIdentity::Gpt {
            disk_guid: [0u8; 16],
            partition_guid: [0u8; 16],
        };
        let uefi = StoreRequest {
            firmware: Firmware::Uefi,
            identity: gpt,
            description: None,
        };
        // Not a hive at all.
        let mut junk = vec![0u8; 600];
        junk[0..4].copy_from_slice(b"nope");
        let err = build(&junk, &uefi).expect_err("bad magic must refuse");
        assert!(err.to_string().contains("not a registry hive"), "{err}");

        // Shorter than the header.
        let err = build(&[0u8; 100], &uefi).expect_err("short input must refuse");
        assert!(
            err.to_string().contains("512-byte registry header"),
            "{err}"
        );

        // Truncated mid-bin: names the byte shortage.
        let mut cut = template_fixture();
        cut.truncate(0x1500);
        let err = build(&cut, &uefi).expect_err("truncated hive must refuse");
        assert!(err.to_string().contains("short by"), "{err}");

        // Missing Objects.
        let mut hive = empty_hive();
        let root = hive.root();
        add_key(&mut hive, root, b"Stray");
        hive.update_checksum().expect("checksum");
        let err = build(&hive.into_bytes(), &uefi).expect_err("no Objects must refuse");
        assert!(err.to_string().contains("System\\Objects"), "{err}");

        // Missing {bootmgr}.
        let mut hive = empty_hive();
        let root = hive.root();
        let objects = add_key(&mut hive, root, b"Objects");
        add_key(&mut hive, objects, OBJECT_MEMDIAG.as_bytes());
        hive.update_checksum().expect("checksum");
        let err = build(&hive.into_bytes(), &uefi).expect_err("no bootmgr must refuse");
        assert!(err.to_string().contains(OBJECT_BOOTMGR), "{err}");

        // Missing loader.
        let bios_request = StoreRequest {
            firmware: Firmware::Bios,
            identity: gpt,
            description: None,
        };
        // The fixture has both loaders, so BIOS succeeds; prove the
        // refusal with a hive that only carries the other flavour.
        let mut minimal = empty_hive();
        let root = minimal.root();
        let objects = add_key(&mut minimal, root, b"Objects");
        let bootmgr = add_key(&mut minimal, objects, OBJECT_BOOTMGR.as_bytes());
        let bootmgr_el = add_key(&mut minimal, bootmgr, b"Elements");
        add_element(
            &mut minimal,
            bootmgr_el,
            "23000003",
            REG_SZ,
            &utf16_nul(TEMPLATE_LOADER_CBD9),
        );
        let uefi_only = add_key(&mut minimal, objects, TEMPLATE_LOADER_B012.as_bytes());
        let uefi_el = add_key(&mut minimal, uefi_only, b"Elements");
        add_element(
            &mut minimal,
            uefi_el,
            "22000002",
            REG_SZ,
            &utf16_nul("\\windows"),
        );
        add_element(
            &mut minimal,
            uefi_el,
            "42000002",
            REG_SZ,
            &utf16_nul("\\system32\\winload.efi"),
        );
        let memdiag = add_key(&mut minimal, objects, OBJECT_MEMDIAG.as_bytes());
        let memdiag_el = add_key(&mut minimal, memdiag, b"Elements");
        add_element(
            &mut minimal,
            memdiag_el,
            "12000002",
            REG_SZ,
            &utf16_nul("\\boot\\memtest.exe"),
        );
        minimal.update_checksum().expect("checksum");
        let minimal_bytes = minimal.into_bytes();
        let err = build(&minimal_bytes, &bios_request).expect_err("no BIOS loader");
        assert!(err.to_string().contains(TEMPLATE_LOADER_A194), "{err}");
        // Sanity: the same hive builds fine for UEFI.
        build(
            &minimal_bytes,
            &StoreRequest {
                firmware: Firmware::Uefi,
                identity: gpt,
                description: None,
            },
        )
        .expect("UEFI loader present");

        // Missing 23000003 on {bootmgr}.
        let mut hive = empty_hive();
        let root = hive.root();
        let objects = add_key(&mut hive, root, b"Objects");
        let bootmgr = add_key(&mut hive, objects, OBJECT_BOOTMGR.as_bytes());
        add_key(&mut hive, bootmgr, b"Elements");
        let loader = add_key(&mut hive, objects, TEMPLATE_LOADER_B012.as_bytes());
        let loader_el = add_key(&mut hive, loader, b"Elements");
        add_element(
            &mut hive,
            loader_el,
            "22000002",
            REG_SZ,
            &utf16_nul("\\windows"),
        );
        add_element(
            &mut hive,
            loader_el,
            "42000002",
            REG_SZ,
            &utf16_nul("\\system32\\winload.efi"),
        );
        let memdiag = add_key(&mut hive, objects, OBJECT_MEMDIAG.as_bytes());
        add_key(&mut hive, memdiag, b"Elements");
        hive.update_checksum().expect("checksum");
        let err = build(&hive.into_bytes(), &uefi).expect_err("no 23000003 must refuse");
        assert!(err.to_string().contains("23000003"), "{err}");

        // Wrong loader flavour suffix.
        let mut bad = template_fixture();
        {
            let mut hive = Hive::parse(&bad).expect("fixture parses");
            let objects = hive
                .find_child(hive.root(), b"Objects")
                .expect("find")
                .expect("objects");
            let loader = hive
                .find_child(objects, TEMPLATE_LOADER_B012.as_bytes())
                .expect("find")
                .expect("loader");
            let elements = hive
                .find_child(loader, b"Elements")
                .expect("find")
                .expect("elements");
            let key = hive
                .find_child(elements, b"42000002")
                .expect("find")
                .expect("suffix element");
            let vk = hive
                .find_value(key, b"Element")
                .expect("find")
                .expect("value");
            hive.set_value_data(vk, REG_SZ, &utf16_nul("\\system32\\winload.exe"))
                .expect("spoil");
            hive.update_checksum().expect("checksum");
            bad = hive.into_bytes();
        }
        let err = build(&bad, &uefi).expect_err("flavour mismatch must refuse");
        assert!(err.to_string().contains("42000002"), "{err}");

        // Missing {memdiag}.
        let mut hive = empty_hive();
        let root = hive.root();
        let objects = add_key(&mut hive, root, b"Objects");
        let bootmgr = add_key(&mut hive, objects, OBJECT_BOOTMGR.as_bytes());
        let bootmgr_el = add_key(&mut hive, bootmgr, b"Elements");
        add_element(
            &mut hive,
            bootmgr_el,
            "23000003",
            REG_SZ,
            &utf16_nul(TEMPLATE_LOADER_CBD9),
        );
        let loader = add_key(&mut hive, objects, TEMPLATE_LOADER_B012.as_bytes());
        let loader_el = add_key(&mut hive, loader, b"Elements");
        add_element(
            &mut hive,
            loader_el,
            "22000002",
            REG_SZ,
            &utf16_nul("\\windows"),
        );
        add_element(
            &mut hive,
            loader_el,
            "42000002",
            REG_SZ,
            &utf16_nul("\\system32\\winload.efi"),
        );
        hive.update_checksum().expect("checksum");
        let err = build(&hive.into_bytes(), &uefi).expect_err("no memdiag must refuse");
        assert!(err.to_string().contains(OBJECT_MEMDIAG), "{err}");

        // Missing required element: the loader has no 22000002 system root.
        let mut hive = empty_hive();
        let root = hive.root();
        let objects = add_key(&mut hive, root, b"Objects");
        let bootmgr = add_key(&mut hive, objects, OBJECT_BOOTMGR.as_bytes());
        let bootmgr_el = add_key(&mut hive, bootmgr, b"Elements");
        add_element(
            &mut hive,
            bootmgr_el,
            "23000003",
            REG_SZ,
            &utf16_nul(TEMPLATE_LOADER_CBD9),
        );
        let loader = add_key(&mut hive, objects, TEMPLATE_LOADER_B012.as_bytes());
        let loader_el = add_key(&mut hive, loader, b"Elements");
        add_element(
            &mut hive,
            loader_el,
            "42000002",
            REG_SZ,
            &utf16_nul("\\system32\\winload.efi"),
        );
        let memdiag = add_key(&mut hive, objects, OBJECT_MEMDIAG.as_bytes());
        let memdiag_el = add_key(&mut hive, memdiag, b"Elements");
        add_element(
            &mut hive,
            memdiag_el,
            "12000002",
            REG_SZ,
            &utf16_nul("\\boot\\memtest.exe"),
        );
        hive.update_checksum().expect("checksum");
        let err = build(&hive.into_bytes(), &uefi).expect_err("no 22000002 must refuse");
        assert!(err.to_string().contains("22000002"), "{err}");

        // Missing required element: {memdiag} has no 12000002 path.
        let mut hive = empty_hive();
        let root = hive.root();
        let objects = add_key(&mut hive, root, b"Objects");
        let bootmgr = add_key(&mut hive, objects, OBJECT_BOOTMGR.as_bytes());
        let bootmgr_el = add_key(&mut hive, bootmgr, b"Elements");
        add_element(
            &mut hive,
            bootmgr_el,
            "23000003",
            REG_SZ,
            &utf16_nul(TEMPLATE_LOADER_CBD9),
        );
        let loader = add_key(&mut hive, objects, TEMPLATE_LOADER_B012.as_bytes());
        let loader_el = add_key(&mut hive, loader, b"Elements");
        add_element(
            &mut hive,
            loader_el,
            "22000002",
            REG_SZ,
            &utf16_nul("\\windows"),
        );
        add_element(
            &mut hive,
            loader_el,
            "42000002",
            REG_SZ,
            &utf16_nul("\\system32\\winload.efi"),
        );
        let memdiag = add_key(&mut hive, objects, OBJECT_MEMDIAG.as_bytes());
        add_key(&mut hive, memdiag, b"Elements");
        hive.update_checksum().expect("checksum");
        let err = build(&hive.into_bytes(), &uefi).expect_err("no memdiag path must refuse");
        assert!(err.to_string().contains("12000002"), "{err}");

        // A description longer than one cell can hold refuses naming
        // the needed bytes and the free space.
        let long_description: String = "X".repeat(3000);
        let err = build(
            &template_fixture(),
            &StoreRequest {
                firmware: Firmware::Uefi,
                identity: gpt,
                description: Some(&long_description),
            },
        )
        .expect_err("oversize description must refuse");
        assert!(err.to_string().contains("are free"), "{err}");

        // Corrupt checksum: flip a header byte inside the checksummed
        // region so the stored checksum no longer matches. (Flipping a
        // byte outside the header would leave the checksum valid.)
        let mut corrupt = template_fixture();
        corrupt[0x10] ^= 0xFF;
        let err = build(&corrupt, &uefi).expect_err("bad checksum must refuse");
        assert!(err.to_string().contains("checksum mismatch"), "{err}");
    }

    /// The real template from the applied Windows image. Ignored by
    /// default: set `RUFUS_TEST_BCD_TEMPLATE` to the extracted
    /// `Windows/System32/config/BCD-Template` path to run it.
    #[test]
    #[ignore]
    fn real_template_builds_both_variants() {
        let Ok(path) = std::env::var("RUFUS_TEST_BCD_TEMPLATE") else {
            println!("skip: RUFUS_TEST_BCD_TEMPLATE is not set");
            return;
        };
        let template = std::fs::read(&path).expect("template must read");
        assert_eq!(&template[0..4], b"regf");
        let gpt = DeviceIdentity::Gpt {
            disk_guid: [
                0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E,
                0x8F, 0x90,
            ],
            partition_guid: [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA,
                0xDC, 0xFE,
            ],
        };
        let mbr = DeviceIdentity::Mbr {
            disk_signature: [0x12, 0x34, 0x56, 0x78],
            partition_start_bytes: 0x0010_0000,
        };
        for (firmware, identity, description) in [
            (Firmware::Uefi, gpt, Some("Windows 11 Enterprise")),
            (Firmware::Bios, mbr, None),
        ] {
            let out = build(
                &template,
                &StoreRequest {
                    firmware,
                    identity,
                    description,
                },
            )
            .expect("real template must build");
            assert_tiling(&out);
            // The real template holds a single 472-byte free cell while
            // a store needs about 1.4 KiB of new cells, so the build
            // appends whole 4 KiB bins: the file stays a whole number of
            // bins and the header length tracks it.
            assert_eq!(out.len() % BIN_SIZE, 0, "output must stay bin-aligned");
            assert!(
                out.len() >= template.len(),
                "output must not shrink the template"
            );
            let header_len = u32::from_le_bytes(
                out[HDR_BIN_LENGTH..HDR_BIN_LENGTH + 4]
                    .try_into()
                    .expect("header length"),
            ) as usize;
            assert_eq!(
                header_len,
                out.len().saturating_sub(BIN_BASE),
                "header hive-bin length must describe the file"
            );
            let hive = Hive::parse(&out).expect("output must re-parse");
            let loader = default_object(firmware);

            let (_, data) = hive
                .element_data(OBJECT_BOOTMGR, ELEMENT_DEFAULT_OBJECT)
                .expect("read")
                .expect("23000003");
            assert_eq!(decode_sz(&data).expect("guid"), loader);

            for (id, want) in [
                (ELEMENT_BOOT_DISPLAY_ORDER, loader),
                (ELEMENT_TOOLS_DISPLAY_ORDER, OBJECT_MEMDIAG),
            ] {
                let (vtype, data) = hive
                    .element_data(OBJECT_BOOTMGR, id)
                    .expect("read")
                    .expect("list");
                assert_eq!(vtype, REG_MULTI_SZ);
                assert_eq!(decode_multisz(&data).expect("list"), vec![want.to_string()]);
            }

            let expected = partition_device(identity);
            for element in [ELEMENT_DEVICE, ELEMENT_OS_DEVICE] {
                let (vtype, data) = hive
                    .element_data(loader, element)
                    .expect("read")
                    .expect("device");
                assert_eq!(vtype, REG_BINARY);
                assert_eq!(data.len(), 88);
                assert_eq!(data, expected.to_vec());
            }
            let (vtype, data) = hive
                .element_data(loader, ELEMENT_PATH)
                .expect("read")
                .expect("12000002");
            assert_eq!(vtype, REG_SZ);
            assert_eq!(decode_sz(&data).expect("path"), winload_full_path(firmware));

            let (vtype, data) = hive
                .element_data(OBJECT_BOOTMGR, ELEMENT_PATH)
                .expect("read")
                .expect("bootmgr 12000002");
            assert_eq!(vtype, REG_SZ);
            let expected_bootmgr_path = match firmware {
                Firmware::Bios => "\\bootmgr",
                Firmware::Uefi => "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
            };
            assert_eq!(decode_sz(&data).expect("path"), expected_bootmgr_path);

            match description {
                Some(text) => {
                    let (_, data) = hive
                        .element_data(loader, ELEMENT_DESCRIPTION)
                        .expect("read")
                        .expect("12000004");
                    assert_eq!(decode_sz(&data).expect("description"), text);
                }
                None => assert!(
                    hive.element_data(loader, ELEMENT_DESCRIPTION)
                        .expect("read")
                        .is_none()
                ),
            }

            let (_, data) = hive
                .element_data(OBJECT_MEMDIAG, ELEMENT_DEVICE)
                .expect("read")
                .expect("memdiag device");
            assert_eq!(data, boot_device().to_vec());
        }
    }
}
