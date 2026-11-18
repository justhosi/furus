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
//! a. Write a store from scratch, rejected: generating a whole hive
//!    would still need the template's settings objects and their GUID
//!    lists, so a small editor on top of the real template is simpler.
//! b. Use the applied image's own `BCD-Template` as a model and build
//!    fresh objects with a small in-crate `regf` editor, kept: minimal
//!    new code, no dependency, and the template supplies the settings
//!    objects, inherited GUID lists and `Description\Type` values a
//!    real `bcdboot` store carries.
//! c. Run the image's `bcdboot`/`bcdedit` under Wine, rejected: Wine
//!    is heavy, needs the user's permission, is untested on this host,
//!    and PLAN calls it the last resort.
//!
//! Decision: candidate (b), implemented here. [`build`] copies the
//! template hive and then *clones* the firmware-selected template
//! loader and its resume object into fresh objects ([`OS_LOADER_UEFI`],
//! [`RESUME_UEFI`] and their BIOS counterparts), modelled on the
//! template keys so they inherit the security descriptor, `Description`
//! key and `14000006`/`16000060`/`17000077` values. The fresh loader
//! gets the per-machine `11000001`/`21000001` partition devices, the
//! full winload `12000002`, the resolved locale (see below), the edition
//! `12000004` when given, `22000002` `\windows` and bcdboot's 8-byte
//! `25000020`/`250000c2`; the fresh resume gets the same device, the
//! full winresume path, the same locale and an 8-byte `25000008`.
//! `{bootmgr}` is repointed at the fresh objects (`23000003`,
//! `23000006`, `24000001`), gets that locale and its own `11000001`
//! partition device (the ESP on UEFI, the system/data partition on
//! BIOS); `{memdiag}` gets that same device and locale, a
//! description and a per-firmware `12000002` path
//! (`\EFI\Microsoft\Boot\memtest.efi` for UEFI, `\boot\memtest.exe`
//! for BIOS, matching where the boot files land), and loses the
//! template's `1600000B`. Class-0x4 setup elements are stripped from
//! the four active objects. Inactive template objects (including the
//! ones the fresh objects were cloned from) are left alone. No other
//! bytes change except the header checksum (and, when the template's
//! own free space runs out, one appended hive bin plus the header
//! length that describes it, see below).
//!
//! Locale precedence for those four objects: the locale supplied by the
//! caller ([`build_with_locale`], wired from the applied tree by
//! [`super::to_go::install`]), else the template's own validated
//! `12000005` ([`locale_in_template`]), else `en-us`. No object gets a
//! hardcoded locale any more.
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
//! prove the encodings the template cannot show: `{bootmgr}` does carry
//! its own `11000001` partition device (pointing at the ESP on UEFI,
//! the system/data partition on BIOS) — its absence on a fresh image
//! is what makes the boot fail with `0xc0000001`, so [`build`] writes
//! it too. `23000003` is a `REG_SZ`
//! GUID string and `24000001`/`24000010` are single-entry `REG_MULTI_SZ`
//! GUID lists. The known-good `bcdboot` store proves the resume and
//! diagnostic devices too: `{memdiag}\11000001` is the very same ESP
//! partition device as `{bootmgr}\11000001`, not the template's locate
//! path or the 88-byte no-disk [`boot_device`]. The BIOS install-media
//! store carries no `12000002` on `{bootmgr}` at all (the firmware
//! default `\bootmgr` applies), so this builder sets
//! `{bootmgr}\12000002` explicitly to `\bootmgr` for BIOS (a shorter
//! string than the template's EFI path, so the in-place shrink path is
//! used) and keeps the template's `\EFI\Microsoft\Boot\bootmgfw.efi`
//! for UEFI.
//!
//! Finally, like `bcdboot`, the builder strips every class-0x4
//! "template element" (the setup-time directives `42000002`,
//! `45000001`, `46000004`, `47000005`, `47000006`, ...) from the four
//! active objects it writes — `{bootmgr}`, the fresh loader, the fresh
//! resume object and `{memdiag}` — before recomputing the checksum. They are
//! not runtime boot elements; leaving them on the active boot path is
//! what makes winload fail with `0xc0000001`. Inactive template objects
//! keep theirs. This needs a regf delete primitive: `regf::Hive` can
//! now unlink a named subkey, compact its parent's subkey list and free
//! the key cell, which is the inverse of its insert path.
//!
//! Allocator and space: the editor allocates new cells from the hive's
//! own free cells first (first fit, splitting a larger free cell,
//! merging with free neighbours when freeing), grows a value or subkey
//! list in place when the cell right after it is free and large enough,
//! and otherwise moves the list to a bigger cell. The real 20 KiB
//! template's small free cells cannot hold the two freshly cloned
//! objects (two object `nk` cells, their `Elements` and `Description`
//! subkeys, a `Description\Type` value and roughly twenty element
//! subkeys with their `vk` and data cells), so the free space alone
//! cannot hold the store. When
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
//! Limitations, stated plainly: a store generated by the image's real
//! `bcdboot c:\windows /s s: /f uefi /v` inside WinPE boots to OOBE
//! under QEMU/OVMF, while the store this builder produced before the
//! fresh-object rewrite always failed with `0xc0000001`. This slice
//! changes only the store construction and does not re-run the image
//! write or QEMU, so boot acceptance of the new bytes is still open.
//! The template above is from Windows 11 24H2; the Windows 10 template
//! has not been inspected, so [`build`] verifies the template loader's
//! `42000002` flavour suffix and the `\windows` system root at build
//! time and refuses rather than cloning from a store it does not
//! recognise.
//!
//! Pipeline wiring is in [`super::to_go`]: it builds both stores and
//! then calls `disable_recovery`, which deliberately still adds
//! `16000009 = 00` to the fresh loader (the known-good store has none).

use std::borrow::Cow;

use super::regf::*;
use crate::error::CoreError;
use crate::error::Result;

/// `{bootmgr}`: the boot manager object both stores update.
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

/// The template BIOS loader (`a1943bbc-...`): `42000002` =
/// `\system32\winload.exe`. [`build`] validates this object's suffix
/// and `\windows` root and clones it into the fresh BIOS loader (see
/// [`OS_LOADER_BIOS`]); it is not the built store's `{default}`.
pub const TEMPLATE_LOADER_A194: &str = "{a1943bbc-ea85-487c-97c7-c9ede908a38a}";

/// The template UEFI loader (`b012b84d-...`): `42000002` =
/// `\system32\winload.efi`. [`build`] validates this object's suffix
/// and `\windows` root and clones it into the fresh UEFI loader (see
/// [`OS_LOADER_UEFI`]); it is not the built store's `{default}`.
pub const TEMPLATE_LOADER_B012: &str = "{b012b84d-c47c-4ed5-b722-c0c42163e569}";

/// Template-only full loader (`cbd971bf-...`): a PE loader carrying
/// both `42000002` (`\system32\winload.exe`) and `42000003`
/// (`\boot.wim`), and the template's initial `{bootmgr}\23000003`
/// default. Never picked as the OS loader (it is the template's
/// placeholder default, repointed by [`build`]).
pub const TEMPLATE_LOADER_CBD9: &str = "{cbd971bf-b7b8-4885-951a-fa03044f5d71}";

/// The `Description\Type` DWORD on a template OS loader object. A
/// `BCD-Template` whose loader uses a non-default GUID is still a usable
/// clone source: when the fixed GUID is absent, [`find_template_object`]
/// falls back to scanning `Objects\*` for this type.
///
/// Provenance: `0x10200003` is the well-known BCD object type for a
/// Windows OS loader (`0x10200000 | 3`), the value Windows writes into
/// `Description\Type`. No real template is checked into this repo, so
/// the constant is a documented assumption of the BCD schema; the
/// ignored `real_template_builds_both_variants` test confirms both
/// constants against a supplied `BCD-Template` (the normal build path
/// takes the fixed-GUID fast path and would never exercise them).
const OBJECT_TYPE_OS_LOADER: u32 = 0x1020_0003;

/// The `Description\Type` DWORD on a template resume object; the fallback
/// counterpart of [`OBJECT_TYPE_OS_LOADER`] (`0x10200004` is the BCD
/// resume-application type, `0x10200000 | 4`). Same provenance: a
/// schema assumption confirmed by `real_template_builds_both_variants`
/// when a real template is supplied.
const OBJECT_TYPE_RESUME: u32 = 0x1020_0004;

/// Fresh UEFI OS loader created by `bcdboot`, and the `{default}` a
/// built UEFI store points at (see [`default_object`]). Its last group
/// is `123456`; the parallel BIOS loader ends in `123457` so the two
/// stores cannot collide.
pub const OS_LOADER_UEFI: &str = "{3796cdc8-e33b-11f1-b950-525400123456}";

/// Fresh BIOS OS loader created by `bcdboot`, and the `{default}` a
/// built BIOS store points at (see [`default_object`]). Its last group
/// is `123457` so it cannot collide with [`OS_LOADER_UEFI`].
pub const OS_LOADER_BIOS: &str = "{3796cdc8-e33b-11f1-b950-525400123457}";

/// Fresh UEFI resume object created by `bcdboot`, wired by the fresh
/// UEFI loader's `23000003` and by `{bootmgr}\23000006`.
pub const RESUME_UEFI: &str = "{3796cdc7-e33b-11f1-b950-525400123456}";

/// Fresh BIOS resume object created by `bcdboot`, wired by the fresh
/// BIOS loader's `23000003` and by `{bootmgr}\23000006`. Its last group
/// is `123457` so it cannot collide with [`RESUME_UEFI`].
pub const RESUME_BIOS: &str = "{3796cdc7-e33b-11f1-b950-525400123457}";

/// `0x11000001` (class `0x11`, device): a partition/boot device element
/// `bcdboot` adds per machine; absent from the template. [`build`]
/// writes it on both fresh objects (the data-partition device), on
/// `{bootmgr}` (the ESP on UEFI, the system/data partition on BIOS) and
/// on `{memdiag}` (the same device as `{bootmgr}`), always as a
/// `REG_BINARY` partition device — see [`partition_device`]. The
/// 88-byte no-disk [`boot_device`] is retained as a helper but is no
/// longer written by the builder.
pub const ELEMENT_DEVICE: u32 = 0x1100_0001;

/// `0x21000001` (class `0x21`, device): the os-device element `bcdboot`
/// adds to the fresh loader per machine; absent from the template.
/// [`build`] writes it as the same 88-byte partition device as
/// `0x11000001`.
pub const ELEMENT_OS_DEVICE: u32 = 0x2100_0001;

/// `0x22000002` (class `0x22`, string): the os device the template
/// loaders carry as a locate-by-path string (`REG_SZ` `\windows`).
/// [`build`] validates that value on the template loader and writes
/// `\windows` on the fresh loader and `\hiberfil.sys` on the fresh
/// resume, matching the good `bcdboot` store.
pub const ELEMENT_OS_LOCATE_PATH: u32 = 0x2200_0002;

/// `0x23000003` (class `0x23`): the default-object element on
/// `{bootmgr}` pointing at the fresh loader, a `REG_SZ` GUID string.
/// The template carries it (pointing at the placeholder loader) and
/// [`build`] refuses a template without it. The same id under the
/// template loader names its resume object and is followed for the
/// inherited values; the fresh loader gets a new `23000003` naming
/// the fresh resume.
pub const ELEMENT_DEFAULT_OBJECT: u32 = 0x2300_0003;

/// `0x23000006` (class `0x23`): the resume-object element on
/// `{bootmgr}`, a `REG_SZ` GUID string naming the resume object that
/// `bcdboot` wires with a device (`11000001`) and a full winresume
/// application path (`12000002`). Absent from the template; [`build`]
/// adds it. Note the loader's *own* resume-object reference is also
/// `0x23000003` ([`ELEMENT_DEFAULT_OBJECT`], read here under the
/// loader), which the template already carries and [`build`] follows.
pub const ELEMENT_RESUME_OBJECT: u32 = 0x2300_0006;

/// `0x24000001` (class `0x24`, GUID list): the boot-manager display
/// order on `{bootmgr}`, a single-entry `REG_MULTI_SZ` holding the
/// fresh loader. Absent from the template; [`build`] adds it.
pub const ELEMENT_BOOT_DISPLAY_ORDER: u32 = 0x2400_0001;

/// `0x24000010` (class `0x24`, GUID list): the tools display order on
/// `{bootmgr}`, a single-entry `REG_MULTI_SZ` holding `{memdiag}`.
/// Absent from the template; [`build`] adds it.
pub const ELEMENT_TOOLS_DISPLAY_ORDER: u32 = 0x2400_0010;

/// `0x12000002` (class `0x12`, string): the boot application path.
/// [`build`] writes the full winload path on the fresh loader, the full
/// winresume path on the fresh resume, sets it to `\bootmgr` on
/// `{bootmgr}` for [`Firmware::Bios`] (keeping the template's EFI path
/// for [`Firmware::Uefi`]), and sets it on `{memdiag}` to
/// [`memdiag_path`] per firmware.
pub const ELEMENT_PATH: u32 = 0x1200_0002;

/// `0x12000004` (class `0x12`, string): the description element;
/// [`build`] sets it to the edition on the fresh loader when the
/// request names one, to `Windows Resume Application` on the fresh
/// resume and to `Windows Memory Diagnostic` on `{memdiag}`.
pub const ELEMENT_DESCRIPTION: u32 = 0x1200_0004;

/// `0x12000005` (class `0x12`, string): the locale element.
pub const ELEMENT_LOCALE: u32 = 0x1200_0005;

/// `0x14000006` (class `0x14`, list): despite the constant name (kept
/// from the slice-5 record), the live template proves this is the
/// inherited-objects list (`BcdLibraryObjectList_InheritedObjects`), a
/// `REG_MULTI_SZ` of GUIDs carried by nearly every object. The
/// boot-manager display order is [`ELEMENT_BOOT_DISPLAY_ORDER`]
/// (`0x24000001`) instead. [`build`] copies this element's value type
/// and bytes from each template object onto its fresh counterpart.
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

/// `0x25000020` (class `0x25`, integer): on the fresh OS loader the
/// `bcdboot` store writes this as an 8-byte all-zero `REG_BINARY` (the
/// template loaders carry a one-byte `00`); no finer role observed.
pub const ELEMENT_25000020: u32 = 0x2500_0020;

/// `0x25000008` (class `0x25`, integer): on the fresh resume object the
/// `bcdboot` store writes this as the 8-byte `REG_BINARY`
/// `0100000000000000` (the template resume carries a one-byte `01`);
/// no finer role observed.
pub const ELEMENT_25000008: u32 = 0x2500_0008;

/// `0x250000C2` (class `0x25`, integer): on the fresh OS loader the
/// `bcdboot` store writes this as the 8-byte `REG_BINARY`
/// `0100000000000000` (the template loaders carry a one-byte `01`);
/// no finer role observed.
pub const ELEMENT_250000C2: u32 = 0x2500_00C2;

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

/// Conservative BCP-47-like locale tag validation: 2-3 ASCII letters,
/// optionally followed by one or more `-` plus 2-8 ASCII alphanumerics.
/// Deliberately stricter than BCP-47 (no single-letter extensions, no
/// non-ASCII): a tag can come from a WIM-supplied directory name or hive
/// value, so only plain, predictable tags are trusted. No regex
/// dependency. Shared with [`super::boot_files::locale_from_tree`].
#[must_use]
pub(crate) fn is_valid_locale_tag(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    let mut i = 0;
    while i < bytes.len() && i < 3 && bytes[i].is_ascii_alphabetic() {
        i += 1;
    }
    if !(2..=3).contains(&i) {
        return false;
    }
    while i < bytes.len() {
        // Each subtag starts with `-` and is 2-8 ASCII alphanumerics.
        if bytes[i] != b'-' {
            return false;
        }
        i += 1;
        let start = i;
        while i < bytes.len() && i - start < 8 && bytes[i].is_ascii_alphanumeric() {
            i += 1;
        }
        if !(2..=8).contains(&(i - start)) {
            return false;
        }
    }
    true
}

/// Which firmware path a store is for; selects the template loader it
/// clones from, the fresh loader object and the application paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Firmware {
    /// UEFI: clone [`TEMPLATE_LOADER_B012`] into [`OS_LOADER_UEFI`]
    /// (`\windows\system32\winload.efi`).
    Uefi,
    /// BIOS: clone [`TEMPLATE_LOADER_A194`] into [`OS_LOADER_BIOS`]
    /// (`\windows\system32\winload.exe`).
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
    /// The target disk identity the device elements encode: the data
    /// (Windows) partition on GPT, the system partition on MBR/BIOS.
    pub identity: DeviceIdentity,
    /// The ESP identity for `{bootmgr}\11000001` on UEFI. `bcdboot`
    /// points the boot manager at the ESP (UEFI) or the system partition
    /// (BIOS); on BIOS paths the build uses [`StoreRequest::identity`]
    /// and this value is ignored.
    pub esp_identity: DeviceIdentity,
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

/// The fresh loader object a built store uses as `{default}`: the
/// `bcdboot`-style UEFI loader for [`Firmware::Uefi`], the parallel BIOS
/// loader for [`Firmware::Bios`]. The store also carries the template
/// loader it was modelled on, but `{bootmgr}` points at this one.
#[must_use]
pub fn default_object(firmware: Firmware) -> &'static str {
    match firmware {
        Firmware::Uefi => OS_LOADER_UEFI,
        Firmware::Bios => OS_LOADER_BIOS,
    }
}

/// The fresh resume object wired by [`default_object`]'s `23000003` and
/// by `{bootmgr}\23000006`, per firmware.
#[must_use]
pub fn default_resume_object(firmware: Firmware) -> &'static str {
    match firmware {
        Firmware::Uefi => RESUME_UEFI,
        Firmware::Bios => RESUME_BIOS,
    }
}

/// The template loader used for validation and as the model for the
/// fresh objects: the UEFI loader for [`Firmware::Uefi`], the BIOS
/// loader for [`Firmware::Bios`]. This is *not* the built store's
/// `{default}` (see [`default_object`]).
fn template_object(firmware: Firmware) -> &'static str {
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

/// The winresume path written as the resume object's `12000002`, per
/// firmware: the full application path `bcdboot` puts on the resume
/// object, not the template's relative `42000002`.
fn winresume_full_path(firmware: Firmware) -> &'static str {
    match firmware {
        Firmware::Uefi => "\\windows\\system32\\winresume.efi",
        Firmware::Bios => "\\windows\\system32\\winresume.exe",
    }
}

/// The `42000002` value the template loader must already carry, per
/// firmware. [`build`] confirms it live before cloning.
fn expected_loader_suffix(firmware: Firmware) -> &'static str {
    match firmware {
        Firmware::Uefi => "\\system32\\winload.efi",
        Firmware::Bios => "\\system32\\winload.exe",
    }
}

/// The `{memdiag}` application path (`12000002`), per firmware: the
/// UEFI memory diagnostics live beside the boot manager on the ESP,
/// while BIOS keeps the template's `\boot\memtest.exe` on the data
/// partition.
fn memdiag_path(firmware: Firmware) -> &'static str {
    match firmware {
        Firmware::Uefi => "\\EFI\\Microsoft\\Boot\\memtest.efi",
        Firmware::Bios => "\\boot\\memtest.exe",
    }
}

/// The 88-byte no-disk boot device (`REG_BINARY`): 16 zero bytes,
/// type 5 (`u32` at `0x10`), zero at `0x14`, length `0x48` (`u32` at
/// `0x18`), zeros after. This is the shape the install-media store
/// puts on `{memdiag}\11000001`. The known-good `bcdboot` store
/// instead uses the ESP partition device there, which is what
/// [`build`] now writes, so this helper is retained for callers and
/// tests but is no longer used by the builder.
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

/// True when `id` belongs to datatype class `0x4`, the BCD "template"
/// class. Per the BCD element reference those ids (`42000002`,
/// `45000001`, `46000004`, `47000005`, `47000006`, ...) are setup-time
/// directives, not runtime boot elements; `bcdboot` strips all of them
/// from the objects it recreates. Class is the top nibble of the top
/// byte, so test the masked byte, not the raw id (0x42 and 0x45 both
/// belong to class 0x4).
fn is_template_element(id: u32) -> bool {
    element_class(id) & 0xF0 == 0x40
}

/// Parse an `Elements\{id}` subkey name (8 hex digits) to its `u32`, or
/// `None` when `name` is not exactly 8 hex digits. Accepts both cases so
/// a template with lowercase element names is still recognised.
fn parse_element_name(name: &[u8]) -> Option<u32> {
    if name.len() != 8 {
        return None;
    }
    let mut id = 0u32;
    for &byte in name {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        id = (id << 4) | u32::from(digit);
    }
    Some(id)
}

/// The ids of every `Elements\{id}` subkey under `elements`, read from
/// the subkey list with the regf list-walk primitives. Names that are
/// not 8 hex digits are skipped (they are not BCD element keys). The
/// caller collects the result before mutating the hive so removal can
/// compact the list without disturbing the iteration.
fn element_ids(hive: &Hive, elements: usize) -> Result<Vec<u32>> {
    let nsub = hive.nk_u32(elements, 0x14, "element count")?;
    if nsub == 0 {
        return Ok(Vec::new());
    }
    let list = hive.nk_u32(elements, 0x1C, "element list")?;
    if list == NONE {
        return Err(CoreError::invalid(format!(
            "bcd Elements key at offset {elements:#x} counts {nsub} elements but has no list"
        )));
    }
    let list = list as usize;
    let (count, _, _, _) = hive.list_head(list)?;
    let mut ids = Vec::with_capacity(count as usize);
    for index in 0..count {
        let Some(child) = hive.list_child(list, index)? else {
            return Err(CoreError::invalid(format!(
                "bcd Elements list at offset {list:#x} lost entry {index}"
            )));
        };
        let (name, _) = hive.nk_name(child)?;
        if let Some(id) = parse_element_name(&name) {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// Remove the `Elements\{id}` subkey under `elements` when it exists;
/// a no-op when it is absent. Element subkey names are the 8 uppercase
/// hex digits from `element_name`, the same shape `set_element` uses to
/// create them.
fn remove_element(hive: &mut Hive, elements: usize, id: u32) -> Result<()> {
    let name = element_name(id);
    hive.remove_child(elements, &name)?;
    Ok(())
}

/// The three runtime values a fresh object inherits from its template
/// counterpart: `14000006` (inherited-object GUID list), `16000060`
/// and `17000077`. Each is kept as the `(value type, bytes)` pair read
/// from the template so a fresh object preserves the original encoding
/// instead of a hard-coded guess. An `Option` is `None` when the
/// template object lacks the element (synthetic fixtures do).
#[derive(Default)]
struct Inherited {
    objects: Option<(u32, Vec<u8>)>,
    flags: Option<(u32, Vec<u8>)>,
    options: Option<(u32, Vec<u8>)>,
}

/// Read [`Inherited`] values from a template object's `Elements` key.
fn read_inherited(hive: &Hive, elements: usize) -> Result<Inherited> {
    Ok(Inherited {
        objects: hive.element_value(elements, ELEMENT_DISPLAY_ORDER)?,
        flags: hive.element_value(elements, ELEMENT_16000060)?,
        options: hive.element_value(elements, ELEMENT_17000077)?,
    })
}

/// Re-set the [`Inherited`] values onto a fresh object's `Elements`
/// key. `14000006` and `17000077` keep the template's value type;
/// `16000060` is a `REG_BINARY` byte in every template read so far and
/// is written through [`Hive::set_element_binary`].
fn write_inherited(hive: &mut Hive, elements: usize, inherited: &Inherited) -> Result<()> {
    if let Some((vtype, data)) = &inherited.objects {
        hive.set_element(elements, ELEMENT_DISPLAY_ORDER, *vtype, data)?;
    }
    if let Some((_, data)) = &inherited.flags {
        hive.set_element_binary(elements, ELEMENT_16000060, data)?;
    }
    if let Some((vtype, data)) = &inherited.options {
        hive.set_element(elements, ELEMENT_17000077, *vtype, data)?;
    }
    Ok(())
}

/// Clone a template object and its two subkeys into fresh keys under
/// `objects`: the object key, its `Elements` key and its `Description`
/// key all take the template key as their `nk` model (so the security
/// descriptor and spare fields match), while `add_child_key` leaves the
/// fresh keys empty. When the template `Description` carries a `Type`
/// DWORD it is copied over as [`REG_DWORD`]. Returns the fresh
/// `Elements` key so the caller can write the runtime elements.
fn clone_object(
    hive: &mut Hive,
    objects: usize,
    guid: &str,
    template_object: usize,
    template_elements: usize,
    template_description: Option<usize>,
) -> Result<usize> {
    let fresh = hive.add_child_key(objects, guid.as_bytes(), Some(template_object))?;
    let fresh_elements = hive.add_child_key(fresh, b"Elements", Some(template_elements))?;
    if let Some(description) = template_description {
        let fresh_description = hive.add_child_key(fresh, b"Description", Some(description))?;
        if let Some((_, data)) = hive.read_value(description, b"Type")? {
            hive.add_value(fresh_description, b"Type", REG_DWORD, &data)?;
        }
    }
    Ok(fresh_elements)
}

/// Read the `Description\Type` DWORD of an object key, when present.
fn description_type(hive: &Hive, object: usize) -> Option<u32> {
    let description = hive.find_child(object, b"Description").ok().flatten()?;
    let (vtype, data) = hive.read_value(description, b"Type").ok().flatten()?;
    if vtype != REG_DWORD || data.len() != 4 {
        return None;
    }
    Some(u32::from_le_bytes(data[..4].try_into().ok()?))
}

/// Resolve a template object by its well-known GUID first, then by its
/// `Description\Type` when that GUID is absent. Some images ship a
/// `BCD-Template` whose loader/resume GUIDs differ from the 24H2 ones
/// pinned above; scanning by the BCD object type still finds the right
/// clone source. A real template carries several objects of the loader
/// type (the minimal ntldr loader and the install-media loader are boot
/// applications too), so the scan returns the byte-wise smallest name
/// *that `accept` approves*: for the loader the caller checks the very
/// same `22000002`/`42000002` values [`build`] later requires, so an
/// unusable object cannot hide a usable one. `accept` never weakens a
/// check — the caller still validates the chosen object.
///
/// The scan is best-effort: a malformed list or sibling key must not
/// abort the build, and the byte-wise ordering keeps it deterministic.
/// In particular the untrusted `Objects` subkey count is cross-checked
/// against the list's own count (as [`Hive::find_child`] does) before
/// any iteration, so a crafted count cannot make us loop billions of
/// times. Callers keep today's "missing object" messages when this
/// returns `Ok(None)`.
fn find_template_object(
    hive: &Hive,
    objects: usize,
    fixed_guid: &str,
    object_type: u32,
    accept: impl Fn(&Hive, usize) -> bool,
) -> Result<Option<usize>> {
    // The fixed-GUID lookup is best-effort too: a corrupt count makes
    // `find_child` fail, and the guarded scan below then reports the
    // familiar "missing object" result instead of an internal error.
    if let Some(key) = hive
        .find_child(objects, fixed_guid.as_bytes())
        .ok()
        .flatten()
    {
        return Ok(Some(key));
    }
    let Ok(nsub) = hive.nk_u32(objects, 0x14, "object count") else {
        return Ok(None);
    };
    if nsub == 0 {
        return Ok(None);
    }
    let Ok(list) = hive.nk_u32(objects, 0x1C, "object list") else {
        return Ok(None);
    };
    if list == NONE {
        return Ok(None);
    }
    let Ok((count, _, _, _)) = hive.list_head(list as usize) else {
        return Ok(None);
    };
    if count != nsub {
        return Ok(None);
    }
    let mut best: Option<(Vec<u8>, usize)> = None;
    for index in 0..count {
        // A forged list entry (or a list that ends early) stops the
        // best-effort scan; it must never turn into a blind `continue`.
        let child = match hive.list_child(list as usize, index) {
            Ok(Some(child)) => child,
            Ok(None) | Err(_) => break,
        };
        if description_type(hive, child) != Some(object_type) {
            continue;
        }
        let Ok((name, _)) = hive.nk_name(child) else {
            continue;
        };
        if !accept(hive, child) {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(best_name, _)| name.as_slice() < best_name.as_slice())
        {
            best = Some((name, child));
        }
    }
    Ok(best.map(|(_, child)| child))
}

/// Read and validate the locale element under one `Elements` key.
fn locale_from_elements(hive: &Hive, elements: usize) -> Option<String> {
    let (_, data) = hive
        .element_value(elements, ELEMENT_LOCALE)
        .ok()
        .flatten()?;
    let tag = decode_sz(&data).ok()?;
    is_valid_locale_tag(&tag).then_some(tag)
}

/// Best-effort locale detection from a parsed template hive: `{bootmgr}`
/// first, then the firmware template loaders resolved by GUID or type.
fn locale_from_hive(hive: &Hive) -> Option<String> {
    // `{memdiag}`'s own 12000005 is deliberately not consulted: the
    // applied tree (locale_from_tree) and then `{bootmgr}`/the template
    // loader are the locale authorities, so a diagnostic object must not
    // be allowed to steer the build. Do not "fix" this by adding it.
    let objects = hive.find_child(hive.root(), b"Objects").ok().flatten()?;
    let bootmgr = hive
        .find_child(objects, OBJECT_BOOTMGR.as_bytes())
        .ok()
        .flatten()?;
    if let Some(elements) = hive.find_child(bootmgr, b"Elements").ok().flatten()
        && let Some(tag) = locale_from_elements(hive, elements)
    {
        return Some(tag);
    }
    for firmware in [Firmware::Uefi, Firmware::Bios] {
        let Some(loader) = find_template_object(
            hive,
            objects,
            template_object(firmware),
            OBJECT_TYPE_OS_LOADER,
            |hive, child| {
                hive.find_child(child, b"Elements")
                    .ok()
                    .flatten()
                    .is_some_and(|elements| locale_from_elements(hive, elements).is_some())
            },
        )
        .ok()
        .flatten() else {
            continue;
        };
        let Some(elements) = hive.find_child(loader, b"Elements").ok().flatten() else {
            continue;
        };
        if let Some(tag) = locale_from_elements(hive, elements) {
            return Some(tag);
        }
    }
    None
}

/// Best-effort locale detection from an applied image's `BCD-Template`
/// bytes: a validated tag from `{bootmgr}` or the firmware template
/// loader, or `None` on any parse, decode or validation failure. This is
/// never an error path; callers fall back to `"en-us"`.
#[must_use]
pub fn locale_in_template(template: &[u8]) -> Option<String> {
    let hive = Hive::parse(template).ok()?;
    locale_from_hive(&hive)
}

/// Build a complete BCD store from a template hive.
///
/// The template is the applied image's `Windows/System32/config/BCD-Template`
/// bytes. Rather than patch the template's objects in place, the build
/// clones the firmware-selected template loader and the resume object it
/// names into *fresh* objects (see [`default_object`] and
/// [`default_resume_object`]) and writes the exact runtime element set
/// real `bcdboot` writes onto them:
///
/// - fresh loader: `11000001`/`21000001` partition devices, the full
///   winload `12000002`, `12000005` with the resolved locale (supplied →
///   template → `en-us`), the edition `12000004` when given,
///   `14000006`/`16000060`/`17000077` inherited from the template
///   loader, `23000003` naming the fresh resume, `22000002` `\windows`,
///   8-byte `25000020` (all zero) and `250000c2` (`0100000000000000`),
///   and no class-0x4 or `16000009` elements;
/// - fresh resume: the same partition device, the full winresume
///   `12000002`, `Windows Resume Application` `12000004`, `12000005`
///   with the same resolved locale, the three inherited values from the
///   template resume, `22000002` `\hiberfil.sys` and 8-byte `25000008`
///   (`0100000000000000`);
/// - `{bootmgr}`: `23000003`, `23000006` and `24000001` repointed at the
///   fresh objects, `12000005` with the same resolved locale, and its
///   own `11000001` partition device (the ESP on UEFI, the system
///   partition on BIOS);
/// - `{memdiag}`: the ESP/system device as `11000001`, `12000005` with
///   the same resolved locale, `Windows Memory Diagnostic` `12000004`,
///   the per-firmware `12000002`, and no `1600000B`.
///
/// Class-0x4 template elements are stripped from these four active
/// objects; inactive template objects are left untouched. The header
/// checksum is recomputed. Refuses with [`CoreError::InvalidInput`]
/// naming what is wrong when the template is not a `regf` hive, is
/// truncated, lacks `System\Objects`, `{bootmgr}`, the firmware
/// template loader, the template resume object or `{memdiag}`, or
/// lacks an element the build has to read.
///
/// The locale written to all four active objects is the one passed to
/// [`build_with_locale`] when given, else the template's own validated
/// `12000005` from `{bootmgr}` or the firmware template loader, else
/// `"en-us"` ([`locale_in_template`] shares that detection).
pub fn build(template: &[u8], request: &StoreRequest<'_>) -> Result<Vec<u8>> {
    build_with_locale(template, request, None)
}

/// Build a store with an explicit locale, falling back to the template's
/// own locale and then to `"en-us"`.
///
/// A supplied `locale` must pass [`is_valid_locale_tag`]; an invalid one
/// is refused with [`CoreError::InvalidInput`] naming it before the hive
/// is parsed or mutated, so it can never be written into the store.
/// Everything else is identical to [`build`].
pub fn build_with_locale(
    template: &[u8],
    request: &StoreRequest<'_>,
    locale: Option<&str>,
) -> Result<Vec<u8>> {
    if let Some(locale) = locale
        && !is_valid_locale_tag(locale)
    {
        return Err(CoreError::invalid(format!(
            "invalid bcd locale {locale}: expected 2-3 ASCII letters optionally followed by -XX subtags of 2-8 ASCII alphanumerics"
        )));
    }
    Ok(build_store(template, request, locale)?.bytes)
}

/// The [`build`] body, keeping the written metadata next to the bytes.
fn build_store(template: &[u8], request: &StoreRequest<'_>, locale: Option<&str>) -> Result<Store> {
    let firmware = request.firmware;
    let template_guid = template_object(firmware);
    let loader_guid = default_object(firmware);
    let resume_guid = default_resume_object(firmware);
    let firmware_name = match firmware {
        Firmware::Uefi => "UEFI",
        Firmware::Bios => "BIOS",
    };
    let mut hive = Hive::parse(template)?;
    // Locale precedence: explicit argument, then the template's own
    // (already validated) locale element, then en-us. The Cow borrows in
    // the common cases and only allocates for a detected tag.
    let effective_locale: Cow<'_, str> = match locale {
        Some(locale) => Cow::Borrowed(locale),
        None => match locale_from_hive(&hive) {
            Some(tag) => Cow::Owned(tag),
            None => Cow::Borrowed("en-us"),
        },
    };
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
    // The template loader is only validated and used as the model for
    // the fresh objects; the built store's {default} is loader_guid.
    // A template without the fixed 24H2 GUID falls back to a scan by
    // Description\Type so non-default object GUIDs still clone. Several
    // real objects carry that type, so the scan only accepts a candidate
    // that passes the very same 22000002/42000002 checks applied below:
    // the minimal ntldr loader and the install-media loader are boot
    // applications too, and must not hide the usable winload loader.
    let expected_suffix = expected_loader_suffix(firmware);
    let template_loader = find_template_object(
        &hive,
        objects,
        template_guid,
        OBJECT_TYPE_OS_LOADER,
        |hive, child| {
            let Some(elements) = hive.find_child(child, b"Elements").ok().flatten() else {
                return false;
            };
            let ok_root = matches!(
                hive.element_value(elements, ELEMENT_OS_LOCATE_PATH),
                Ok(Some((REG_SZ, data))) if decode_sz(&data).is_ok_and(|s| s == "\\windows")
            );
            let ok_loader = matches!(
                hive.element_value(elements, ELEMENT_LOADER_PATH),
                Ok(Some((REG_SZ, data))) if decode_sz(&data).is_ok_and(|s| s == expected_suffix)
            );
            ok_root && ok_loader
        },
    )?
    .ok_or_else(|| {
        CoreError::invalid(format!(
            "bcd template is missing the {firmware_name} loader object {template_guid}"
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
    let loader_elements = hive
        .find_child(template_loader, b"Elements")?
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd template loader {template_guid} has no Elements key"
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
                "bcd template loader {template_guid} has no \\\\windows 22000002 system root to keep"
            )));
        }
        None => {
            return Err(CoreError::invalid(format!(
                "bcd template loader {template_guid} has no 22000002 element to keep"
            )));
        }
    }
    match hive.element_value(loader_elements, ELEMENT_LOADER_PATH)? {
        Some((REG_SZ, data)) if decode_sz(&data)? == expected_suffix => {}
        Some((_, data)) => {
            let found = decode_sz(&data).unwrap_or_else(|_| "<not UTF-16>".to_string());
            return Err(CoreError::invalid(format!(
                "bcd template loader {template_guid} carries 42000002 {found}, expected {expected_suffix}"
            )));
        }
        None => {
            return Err(CoreError::invalid(format!(
                "bcd template loader {template_guid} has no 42000002 element to confirm"
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
    // Follow the template loader's 23000003 to its resume object, then
    // read the values the fresh objects inherit. All of this happens
    // before any mutation so the cells stay put while we write.
    let template_resume_guid = match hive.element_value(loader_elements, ELEMENT_DEFAULT_OBJECT)? {
        Some((_, data)) => decode_sz(&data)?,
        None => {
            return Err(CoreError::invalid(format!(
                "bcd template loader {template_guid} has no 23000003 resume object to wire"
            )));
        }
    };
    // Several objects might carry the resume type too; keep the first
    // that has the `Elements` key the build reads below. The 23000003
    // GUID still wins whenever it resolves, as before.
    let template_resume = find_template_object(
        &hive,
        objects,
        &template_resume_guid,
        OBJECT_TYPE_RESUME,
        |hive, child| hive.find_child(child, b"Elements").ok().flatten().is_some(),
    )?
    .ok_or_else(|| {
        CoreError::invalid(format!(
            "bcd template is missing the resume object {template_resume_guid}"
        ))
    })?;
    let template_resume_elements =
        hive.find_child(template_resume, b"Elements")?
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd template resume object {template_resume_guid} has no Elements key"
                ))
            })?;
    let loader_inherited = read_inherited(&hive, loader_elements)?;
    let resume_inherited = read_inherited(&hive, template_resume_elements)?;
    let template_loader_description = hive.find_child(template_loader, b"Description")?;
    let template_resume_description = hive.find_child(template_resume, b"Description")?;

    let partition = partition_device(request.identity);
    // bcdboot writes `{bootmgr}\11000001` as a partition device pointing
    // at the ESP on UEFI (the system partition on BIOS). Its absence on a
    // freshly written UEFI image is what lands the boot in a Recovery
    // screen with 0xc0000001, so add it here with the ESP identity; on
    // BIOS the boot manager shares the system partition with the loader.
    // `{memdiag}` gets the very same device bytes.
    let bootmgr_device = match firmware {
        Firmware::Uefi => partition_device(request.esp_identity),
        Firmware::Bios => partition,
    };

    // Repoint {bootmgr} at the fresh objects and write the resolved locale.
    // 24000010, 25000004, 12000002 and 12000004 are left alone.
    hive.set_element_sz(bootmgr_elements, ELEMENT_DEFAULT_OBJECT, loader_guid)?;
    hive.set_element_sz(bootmgr_elements, ELEMENT_LOCALE, effective_locale.as_ref())?;
    hive.set_element_sz(bootmgr_elements, ELEMENT_RESUME_OBJECT, resume_guid)?;
    hive.set_element_multisz(bootmgr_elements, ELEMENT_BOOT_DISPLAY_ORDER, &[loader_guid])?;
    hive.set_element_multisz(
        bootmgr_elements,
        ELEMENT_TOOLS_DISPLAY_ORDER,
        &[OBJECT_MEMDIAG],
    )?;
    if firmware == Firmware::Bios {
        hive.set_element_sz(bootmgr_elements, ELEMENT_PATH, "\\bootmgr")?;
    };
    hive.set_element_binary(bootmgr_elements, ELEMENT_DEVICE, &bootmgr_device)?;

    // Fresh OS loader: exactly the element set bcdboot writes, with the
    // three inherited values copied from the template loader. No
    // class-0x4 setup elements, no 16000009 (that would be added later
    // by `disable_recovery`, which is deliberately left unchanged).
    let fresh_loader_elements = clone_object(
        &mut hive,
        objects,
        loader_guid,
        template_loader,
        loader_elements,
        template_loader_description,
    )?;
    hive.set_element_binary(fresh_loader_elements, ELEMENT_DEVICE, &partition)?;
    hive.set_element_binary(fresh_loader_elements, ELEMENT_OS_DEVICE, &partition)?;
    hive.set_element_sz(
        fresh_loader_elements,
        ELEMENT_PATH,
        winload_full_path(firmware),
    )?;
    if let Some(description) = request.description {
        hive.set_element_sz(fresh_loader_elements, ELEMENT_DESCRIPTION, description)?;
    }
    hive.set_element_sz(
        fresh_loader_elements,
        ELEMENT_LOCALE,
        effective_locale.as_ref(),
    )?;
    write_inherited(&mut hive, fresh_loader_elements, &loader_inherited)?;
    hive.set_element_sz(fresh_loader_elements, ELEMENT_DEFAULT_OBJECT, resume_guid)?;
    hive.set_element_binary(fresh_loader_elements, ELEMENT_25000020, &[0u8; 8])?;
    hive.set_element_binary(
        fresh_loader_elements,
        ELEMENT_250000C2,
        &[1, 0, 0, 0, 0, 0, 0, 0],
    )?;
    hive.set_element_sz(fresh_loader_elements, ELEMENT_OS_LOCATE_PATH, "\\windows")?;

    // Fresh resume object, mirroring the template resume's inherited
    // values but with bcdboot's runtime shapes (8-byte 25000008, full
    // winresume path and description).
    let fresh_resume_elements = clone_object(
        &mut hive,
        objects,
        resume_guid,
        template_resume,
        template_resume_elements,
        template_resume_description,
    )?;
    hive.set_element_binary(fresh_resume_elements, ELEMENT_DEVICE, &partition)?;
    hive.set_element_sz(
        fresh_resume_elements,
        ELEMENT_PATH,
        winresume_full_path(firmware),
    )?;
    hive.set_element_sz(
        fresh_resume_elements,
        ELEMENT_DESCRIPTION,
        "Windows Resume Application",
    )?;
    hive.set_element_sz(
        fresh_resume_elements,
        ELEMENT_LOCALE,
        effective_locale.as_ref(),
    )?;
    write_inherited(&mut hive, fresh_resume_elements, &resume_inherited)?;
    hive.set_element_binary(
        fresh_resume_elements,
        ELEMENT_25000008,
        &[1, 0, 0, 0, 0, 0, 0, 0],
    )?;
    hive.set_element_sz(
        fresh_resume_elements,
        ELEMENT_OS_LOCATE_PATH,
        "\\hiberfil.sys",
    )?;

    // {memdiag}: ESP/system device, the resolved locale, a description,
    // the per-firmware path, and drop the template's 1600000B.
    hive.set_element_binary(memdiag_elements, ELEMENT_DEVICE, &bootmgr_device)?;
    hive.set_element_sz(memdiag_elements, ELEMENT_LOCALE, effective_locale.as_ref())?;
    hive.set_element_sz(
        memdiag_elements,
        ELEMENT_DESCRIPTION,
        "Windows Memory Diagnostic",
    )?;
    hive.set_element_sz(memdiag_elements, ELEMENT_PATH, memdiag_path(firmware))?;
    remove_element(&mut hive, memdiag_elements, ELEMENT_1600000B)?;

    // Strip every class-0x4 "template element" — the setup-time
    // directives (42000002, 45000001, 46000004, 47000005, 47000006,
    // ...) — from the four active objects. They are not runtime boot
    // elements; leaving them on the active boot path is what makes
    // winload fail with 0xc0000001. Inactive template objects (including
    // the loader and PE loader we modelled the fresh ones on) keep
    // theirs, so we do not delete those objects: they are harmless and
    // removing them risks breaking a live reference we did not check.
    for elements in [
        bootmgr_elements,
        fresh_loader_elements,
        fresh_resume_elements,
        memdiag_elements,
    ] {
        for id in element_ids(&hive, elements)? {
            if is_template_element(id) {
                remove_element(&mut hive, elements, id)?;
            }
        }
    }

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
        let table: [(u32, u32, u8); 29] = [
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
            (0x2300_0006, ELEMENT_RESUME_OBJECT, 0x23),
            (0x2400_0001, ELEMENT_BOOT_DISPLAY_ORDER, 0x24),
            (0x2400_0010, ELEMENT_TOOLS_DISPLAY_ORDER, 0x24),
            (0x2500_0004, ELEMENT_TIMEOUT, 0x25),
            (0x2500_0008, ELEMENT_25000008, 0x25),
            (0x2500_0020, ELEMENT_25000020, 0x25),
            (0x2500_00C2, ELEMENT_250000C2, 0x25),
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
            OS_LOADER_UEFI,
            OS_LOADER_BIOS,
            RESUME_UEFI,
            RESUME_BIOS,
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
        assert_eq!(OS_LOADER_UEFI, "{3796cdc8-e33b-11f1-b950-525400123456}");
        assert_eq!(OS_LOADER_BIOS, "{3796cdc8-e33b-11f1-b950-525400123457}");
        assert_eq!(RESUME_UEFI, "{3796cdc7-e33b-11f1-b950-525400123456}");
        assert_eq!(RESUME_BIOS, "{3796cdc7-e33b-11f1-b950-525400123457}");
    }

    #[test]
    fn bootmgr_guid_bytes_render_as_the_bootmgr_identifier() {
        // The on-disk little-endian bytes of {bootmgr} through the
        // shared mixed-endian formatter must equal the constant the
        // builder matches against.
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
    fn default_object_selects_the_fresh_loader_and_resume_per_firmware() {
        // The built store's {default} is the fresh bcdboot-style loader,
        // not the template object it was modelled on.
        assert_eq!(default_object(Firmware::Uefi), OS_LOADER_UEFI);
        assert_eq!(default_object(Firmware::Bios), OS_LOADER_BIOS);
        assert_eq!(default_resume_object(Firmware::Uefi), RESUME_UEFI);
        assert_eq!(default_resume_object(Firmware::Bios), RESUME_BIOS);
        assert_eq!(
            default_object(Firmware::Uefi),
            "{3796cdc8-e33b-11f1-b950-525400123456}"
        );
        assert_eq!(
            default_object(Firmware::Bios),
            "{3796cdc8-e33b-11f1-b950-525400123457}"
        );
        // The two firmware stores cannot collide: their loader and
        // resume GUIDs differ in the last hex digit.
        assert_ne!(
            default_object(Firmware::Uefi),
            default_object(Firmware::Bios)
        );
        assert_ne!(
            default_resume_object(Firmware::Uefi),
            default_resume_object(Firmware::Bios)
        );
        assert_ne!(
            default_object(Firmware::Uefi),
            template_object(Firmware::Uefi)
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

    /// Start a minimal hive: header plus four bins holding a `System`
    /// root key and free space, so the fixture and the stores built
    /// from it (which now clone two fresh objects with their own
    /// `Elements`/`Description` keys) fit without appending bins.
    fn empty_hive() -> Hive {
        let mut buf = vec![0u8; 0x200];
        buf[0..4].copy_from_slice(b"regf");
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        buf[8..12].copy_from_slice(&1u32.to_le_bytes());
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        buf[0x18..0x1C].copy_from_slice(&3u32.to_le_bytes());
        buf[HDR_ROOT..HDR_ROOT + 4].copy_from_slice(&0x20u32.to_le_bytes());
        buf[HDR_BIN_LENGTH..HDR_BIN_LENGTH + 4].copy_from_slice(&0x4000u32.to_le_bytes());
        buf.resize(0x5000, 0);
        for bin in [0x1000usize, 0x2000, 0x3000, 0x4000] {
            buf[bin..bin + 4].copy_from_slice(b"hbin");
            buf[bin + 4..bin + 8].copy_from_slice(&(bin as u32).wrapping_sub(0x1000).to_le_bytes());
            buf[bin + 8..bin + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        }
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
        // The other three bins each stay one free cell.
        for free in [0x2020usize, 0x3020, 0x4020] {
            buf[free..free + 4].copy_from_slice(&(HBIN_USABLE as i32).to_le_bytes());
        }
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

    /// The resume object the template's loaders reference: `bcdboot`
    /// wires this object with a device and a full winresume path.
    const TEST_RESUME_GUID: &str = "{0c334284-9a41-4de1-99b3-a7e87e8ff07e}";

    /// Build a template-shaped fixture: `System\Objects` with
    /// `{bootmgr}`, both winload loaders, the resume object they point
    /// at and `{memdiag}`, each with an `Elements` key holding the
    /// elements [`build`] reads.
    fn template_fixture() -> Vec<u8> {
        let mut hive = empty_hive();
        let root = hive.root();
        let objects = add_key(&mut hive, root, b"Objects");
        let bootmgr = add_key(&mut hive, objects, OBJECT_BOOTMGR.as_bytes());
        let uefi = add_key(&mut hive, objects, TEMPLATE_LOADER_B012.as_bytes());
        let bios = add_key(&mut hive, objects, TEMPLATE_LOADER_A194.as_bytes());
        let resume = add_key(&mut hive, objects, TEST_RESUME_GUID.as_bytes());
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
        // Template-class setup elements bcdboot strips from the active
        // boot path. Their presence in the fixture proves the strip.
        add_element(&mut hive, bootmgr_el, "45000001", REG_BINARY, &[0x01]);
        add_element(&mut hive, bootmgr_el, "47000006", REG_BINARY, &[0x10]);

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
            add_element(
                &mut hive,
                elements,
                "23000003",
                REG_SZ,
                &utf16_nul(TEST_RESUME_GUID),
            );
            add_element(&mut hive, elements, "45000001", REG_BINARY, &[0x02]);
            add_element(&mut hive, elements, "47000005", REG_BINARY, &[0x01]);
            add_element(&mut hive, elements, "47000006", REG_BINARY, &[0x10]);
        }

        let resume_el = add_key(&mut hive, resume, b"Elements");
        add_element(
            &mut hive,
            resume_el,
            "42000002",
            REG_SZ,
            &utf16_nul("\\system32\\winresume.efi"),
        );
        add_element(&mut hive, resume_el, "45000001", REG_BINARY, &[0x02]);

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
        add_element(&mut hive, memdiag_el, "45000001", REG_BINARY, &[0x01]);
        add_element(&mut hive, memdiag_el, "47000005", REG_BINARY, &[0x01]);

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
        let esp = DeviceIdentity::Gpt {
            disk_guid: [0x0E; 16],
            partition_guid: [0x5E; 16],
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
                esp_identity: esp,
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
            // The good bcdboot store gives {memdiag} the same partition
            // device as {bootmgr}: the ESP on UEFI, the system/data
            // partition on BIOS.
            let expected_boot_device = match firmware {
                Firmware::Uefi => partition_device(esp),
                Firmware::Bios => partition_device(identity),
            };
            assert_eq!(data, expected_boot_device.to_vec());
            let (_, bootmgr_device) = hive
                .element_data(OBJECT_BOOTMGR, ELEMENT_DEVICE)
                .expect("read bootmgr device")
                .expect("bootmgr 11000001 must exist");
            assert_eq!(data, bootmgr_device, "memdiag and bootmgr share a device");

            // The memory-diagnostic application path is per firmware:
            // the UEFI diagnostics live on the ESP next to the boot
            // manager, while BIOS keeps the template's data-partition
            // path.
            let (vtype, data) = hive
                .element_data(OBJECT_MEMDIAG, ELEMENT_PATH)
                .expect("read memdiag path")
                .expect("memdiag 12000002 must survive");
            assert_eq!(vtype, REG_SZ);
            assert_eq!(decode_sz(&data).expect("path text"), memdiag_path(firmware));
        }
    }

    #[test]
    fn bootmgr_device_points_at_esp_on_uefi_and_system_partition_on_bios() {
        // bcdboot writes `{bootmgr}\11000001` as a partition device aimed
        // at the ESP on UEFI (the system/data partition on BIOS). Its
        // absence on a fresh UEFI image is the 0xc0000001 root cause, so
        // pin both its presence and the exact bytes, and keep the two
        // identities distinct so the assertions cannot pass by accident.
        let data = DeviceIdentity::Gpt {
            disk_guid: [0x01; 16],
            partition_guid: [0x0A; 16],
        };
        let esp = DeviceIdentity::Gpt {
            disk_guid: [0x01; 16],
            partition_guid: [0x0B; 16],
        };
        assert_ne!(data, esp, "the fixture identities must be distinct");

        for (firmware, want, wrong) in [
            (
                Firmware::Uefi,
                partition_device(esp),
                partition_device(data),
            ),
            (
                Firmware::Bios,
                partition_device(data),
                partition_device(esp),
            ),
        ] {
            let out = build(
                &template_fixture(),
                &StoreRequest {
                    firmware,
                    identity: data,
                    esp_identity: esp,
                    description: None,
                },
            )
            .expect("build must succeed");
            let hive = Hive::parse(&out).expect("output must re-parse");
            let (vtype, bytes) = hive
                .element_data(OBJECT_BOOTMGR, ELEMENT_DEVICE)
                .expect("read bootmgr device")
                .expect("bootmgr 11000001 must exist");
            assert_eq!(vtype, REG_BINARY);
            assert_eq!(
                bytes,
                want.to_vec(),
                "bootmgr device bytes for {firmware:?}"
            );
            assert_ne!(
                bytes,
                wrong.to_vec(),
                "bootmgr must not point at the other partition on {firmware:?}"
            );
        }
    }

    #[test]
    fn resume_object_is_wired_like_bcdboot() {
        let template = template_fixture();
        let out = build(
            &template,
            &StoreRequest {
                firmware: Firmware::Uefi,
                identity: DeviceIdentity::Gpt {
                    disk_guid: [0x01; 16],
                    partition_guid: [0x0A; 16],
                },
                esp_identity: DeviceIdentity::Gpt {
                    disk_guid: [0x01; 16],
                    partition_guid: [0x0B; 16],
                },
                description: None,
            },
        )
        .expect("build must succeed");
        let hive = Hive::parse(&out).expect("output must re-parse");
        let loader = default_object(Firmware::Uefi);
        let resume = default_resume_object(Firmware::Uefi);

        // (a) the fresh resume object's device is the same partition
        // device the fresh loader got, byte for byte.
        let (vtype, resume_device) = hive
            .element_data(resume, ELEMENT_DEVICE)
            .expect("read resume device")
            .expect("resume 11000001 must exist");
        assert_eq!(vtype, REG_BINARY);
        let (_, loader_device) = hive
            .element_data(loader, ELEMENT_DEVICE)
            .expect("read loader device")
            .expect("loader 11000001 must exist");
        assert_eq!(resume_device, loader_device);

        // (b) the full winresume application path, not the template's
        // relative 42000002.
        let (vtype, data) = hive
            .element_data(resume, ELEMENT_PATH)
            .expect("read resume path")
            .expect("resume 12000002 must exist");
        assert_eq!(vtype, REG_SZ);
        assert_eq!(
            decode_sz(&data).expect("path text"),
            winresume_full_path(Firmware::Uefi)
        );
        assert_eq!(
            decode_sz(&data).expect("path text"),
            "\\windows\\system32\\winresume.efi"
        );

        // (c) both the loader and bootmgr point at the fresh resume.
        let (vtype, data) = hive
            .element_data(loader, ELEMENT_DEFAULT_OBJECT)
            .expect("read loader resume ref")
            .expect("loader 23000003 must exist");
        assert_eq!(vtype, REG_SZ);
        assert_eq!(decode_sz(&data).expect("guid text"), resume);
        let (vtype, data) = hive
            .element_data(OBJECT_BOOTMGR, ELEMENT_RESUME_OBJECT)
            .expect("read resume object ref")
            .expect("bootmgr 23000006 must exist");
        assert_eq!(vtype, REG_SZ);
        assert_eq!(decode_sz(&data).expect("guid text"), resume);
        assert_ne!(resume, TEST_RESUME_GUID, "the resume must be fresh");
    }

    /// Enumerate the element ids under `object`'s `Elements` key in a
    /// parsed hive, using the same list-walk helper as the strip step.
    fn object_element_ids(hive: &Hive, object: &str) -> Vec<u32> {
        let objects = hive
            .find_child(hive.root(), b"Objects")
            .expect("find Objects")
            .expect("Objects key");
        let obj = hive
            .find_child(objects, object.as_bytes())
            .expect("find object")
            .expect("object key");
        let elements = hive
            .find_child(obj, b"Elements")
            .expect("find Elements")
            .expect("Elements key");
        element_ids(hive, elements).expect("element ids")
    }

    #[test]
    fn template_class_elements_are_stripped_from_boot_path() {
        let gpt = DeviceIdentity::Gpt {
            disk_guid: [0x01; 16],
            partition_guid: [0x0A; 16],
        };
        for firmware in [Firmware::Uefi, Firmware::Bios] {
            let template = template_fixture();
            let loader = default_object(firmware);
            let resume = default_resume_object(firmware);

            // Pre-condition: the template objects the build clones from
            // really do carry at least one template-class element, and
            // so do the two objects we strip in place ({bootmgr} and
            // {memdiag}); otherwise the strip assertions are vacuous. The
            // fresh objects start empty, so they are tested afterwards.
            {
                let fixture = Hive::parse(&template).expect("fixture parses");
                for object in [
                    OBJECT_BOOTMGR,
                    template_object(firmware),
                    TEST_RESUME_GUID,
                    OBJECT_MEMDIAG,
                ] {
                    let ids = object_element_ids(&fixture, object);
                    assert!(
                        ids.iter().any(|&id| is_template_element(id)),
                        "{object} fixture must carry a template element before build"
                    );
                }
            }

            let out = build(
                &template,
                &StoreRequest {
                    firmware,
                    identity: gpt,
                    esp_identity: gpt,
                    description: Some("Windows 11 Pro"),
                },
            )
            .expect("build must succeed");
            assert_tiling(&out);
            let hive = Hive::parse(&out).expect("output must re-parse");

            // No template-class element survives on any of the four
            // active boot-path objects. Inactive template objects (the
            // other loaders, {legacy}, ...) are left untouched.
            for object in [OBJECT_BOOTMGR, loader, resume, OBJECT_MEMDIAG] {
                for id in object_element_ids(&hive, object) {
                    assert!(
                        !is_template_element(id),
                        "{object} must have no template element, found {id:#010x}"
                    );
                }
            }

            // The runtime elements are all still there.
            let bootmgr_ids = object_element_ids(&hive, OBJECT_BOOTMGR);
            for id in [
                ELEMENT_DEFAULT_OBJECT,
                ELEMENT_BOOT_DISPLAY_ORDER,
                ELEMENT_TOOLS_DISPLAY_ORDER,
                ELEMENT_PATH,
                ELEMENT_TIMEOUT,
                ELEMENT_RESUME_OBJECT,
            ] {
                assert!(
                    bootmgr_ids.contains(&id),
                    "bootmgr must keep runtime element {id:#010x}"
                );
            }
            let loader_ids = object_element_ids(&hive, loader);
            for id in [
                ELEMENT_DEVICE,
                ELEMENT_OS_DEVICE,
                ELEMENT_PATH,
                ELEMENT_OS_LOCATE_PATH,
                ELEMENT_DEFAULT_OBJECT,
                ELEMENT_DESCRIPTION,
            ] {
                assert!(
                    loader_ids.contains(&id),
                    "loader must keep runtime element {id:#010x}"
                );
            }
            let resume_ids = object_element_ids(&hive, resume);
            for id in [ELEMENT_DEVICE, ELEMENT_PATH] {
                assert!(
                    resume_ids.contains(&id),
                    "resume object must keep runtime element {id:#010x}"
                );
            }
            let memdiag_ids = object_element_ids(&hive, OBJECT_MEMDIAG);
            for id in [ELEMENT_DEVICE, ELEMENT_PATH, ELEMENT_LOCALE] {
                assert!(
                    memdiag_ids.contains(&id),
                    "memdiag must keep runtime element {id:#010x}"
                );
            }
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
            esp_identity: gpt,
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
            esp_identity: gpt,
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
        add_element(
            &mut minimal,
            uefi_el,
            "23000003",
            REG_SZ,
            &utf16_nul(TEST_RESUME_GUID),
        );
        let resume = add_key(&mut minimal, objects, TEST_RESUME_GUID.as_bytes());
        add_key(&mut minimal, resume, b"Elements");
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
                esp_identity: gpt,
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

        // Missing resume object: the loader has no 23000003 to name one.
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
        let memdiag_el = add_key(&mut hive, memdiag, b"Elements");
        add_element(
            &mut hive,
            memdiag_el,
            "12000002",
            REG_SZ,
            &utf16_nul("\\boot\\memtest.exe"),
        );
        hive.update_checksum().expect("checksum");
        let err = build(&hive.into_bytes(), &uefi).expect_err("no resume object must refuse");
        assert!(err.to_string().contains("resume object"), "{err}");

        // A description longer than one cell can hold refuses naming
        // the needed bytes and the free space.
        let long_description: String = "X".repeat(3000);
        let err = build(
            &template_fixture(),
            &StoreRequest {
                firmware: Firmware::Uefi,
                identity: gpt,
                esp_identity: gpt,
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
        // The normal build path uses the fixed GUIDs, so it never proves
        // the OBJECT_TYPE_* constants. Confirm them directly against a
        // real template here when one is supplied: the OS loader's
        // Description\Type and the resume object it names.
        {
            let template_hive = Hive::parse(&template).expect("template must parse");
            let objects = template_hive
                .find_child(template_hive.root(), b"Objects")
                .expect("find")
                .expect("objects");
            let loader = template_hive
                .find_child(objects, TEMPLATE_LOADER_B012.as_bytes())
                .expect("find")
                .expect("uefi template loader");
            assert_eq!(
                description_type(&template_hive, loader),
                Some(OBJECT_TYPE_OS_LOADER),
                "real template OS loader Description\\Type must match the constant"
            );
            let loader_elements = template_hive
                .find_child(loader, b"Elements")
                .expect("find")
                .expect("loader Elements");
            let (_, resume_ref) = template_hive
                .element_value(loader_elements, ELEMENT_DEFAULT_OBJECT)
                .expect("read")
                .expect("loader 23000003");
            let resume_guid = decode_sz(&resume_ref).expect("resume guid text");
            let resume = template_hive
                .find_child(objects, resume_guid.as_bytes())
                .expect("find")
                .expect("resume object");
            assert_eq!(
                description_type(&template_hive, resume),
                Some(OBJECT_TYPE_RESUME),
                "real template resume Description\\Type must match the constant"
            );
        }
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
                    esp_identity: gpt,
                    description,
                },
            )
            .expect("real template must build");
            assert_tiling(&out);
            // The real template's own free cells cannot hold the two
            // freshly cloned objects and their elements, so the build
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

            // Real-hive coverage for the strip: no class-0x4 template
            // element survives on any of the four active boot-path
            // objects. Resolve the resume object from the loader's own
            // 23000003 reference (its GUID is per-template).
            let (_, resume_bytes) = hive
                .element_data(loader, ELEMENT_DEFAULT_OBJECT)
                .expect("read loader resume ref")
                .expect("loader 23000003");
            let resume_guid = decode_sz(&resume_bytes).expect("resume guid text");
            assert_eq!(resume_guid, default_resume_object(firmware));
            for object in [OBJECT_BOOTMGR, loader, resume_guid.as_str(), OBJECT_MEMDIAG] {
                for id in object_element_ids(&hive, object) {
                    assert!(
                        !is_template_element(id),
                        "{object} must have no template element, found {id:#010x}"
                    );
                }
            }

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
            // bcdboot gives {memdiag} the same ESP/system partition
            // device as {bootmgr}, not the 88-byte no-disk boot device.
            let (_, bootmgr_device_bytes) = hive
                .element_data(OBJECT_BOOTMGR, ELEMENT_DEVICE)
                .expect("read")
                .expect("bootmgr device");
            assert_eq!(data, bootmgr_device_bytes);

            let (vtype, data) = hive
                .element_data(OBJECT_MEMDIAG, ELEMENT_PATH)
                .expect("read")
                .expect("memdiag 12000002");
            assert_eq!(vtype, REG_SZ);
            assert_eq!(decode_sz(&data).expect("path"), memdiag_path(firmware));
        }
    }

    /// Focused regression for the bcdboot-shaped store: the boot
    /// manager points at fresh objects (not the template's), their
    /// device/locale/integer elements have bcdboot's exact shapes, and
    /// the recovery/template elements the known-good store lacks are
    /// absent. `template_fixture` is the fixture the other build tests
    /// use, so this runs in the ordinary test suite.
    #[test]
    fn fresh_objects_match_bcdboot_element_shapes() {
        let data = DeviceIdentity::Gpt {
            disk_guid: [0x01; 16],
            partition_guid: [0x0A; 16],
        };
        let esp = DeviceIdentity::Gpt {
            disk_guid: [0x01; 16],
            partition_guid: [0x0B; 16],
        };
        assert_ne!(data, esp, "the fixture identities must be distinct");
        let out = build(
            &template_fixture(),
            &StoreRequest {
                firmware: Firmware::Uefi,
                identity: data,
                esp_identity: esp,
                description: Some("Windows 11"),
            },
        )
        .expect("build must succeed");
        assert_tiling(&out);
        let hive = Hive::parse(&out).expect("output must re-parse");
        let loader = default_object(Firmware::Uefi);
        let resume = default_resume_object(Firmware::Uefi);
        assert_ne!(
            loader,
            template_object(Firmware::Uefi),
            "{{default}} must be the fresh loader, not the template's"
        );

        // {bootmgr} points at both fresh objects.
        for (id, want) in [
            (ELEMENT_DEFAULT_OBJECT, loader),
            (ELEMENT_RESUME_OBJECT, resume),
        ] {
            let (vtype, got) = hive
                .element_data(OBJECT_BOOTMGR, id)
                .expect("read")
                .expect("bootmgr reference");
            assert_eq!(vtype, REG_SZ);
            assert_eq!(decode_sz(&got).expect("guid"), want);
        }
        let (vtype, got) = hive
            .element_data(OBJECT_BOOTMGR, ELEMENT_BOOT_DISPLAY_ORDER)
            .expect("read")
            .expect("24000001");
        assert_eq!(vtype, REG_MULTI_SZ);
        assert_eq!(
            decode_multisz(&got).expect("list"),
            vec![loader.to_string()]
        );

        // Fresh loader: partition devices, en-us, 8-byte integers, no
        // recovery element and no class-0x4 setup elements.
        let expected = partition_device(data);
        for id in [ELEMENT_DEVICE, ELEMENT_OS_DEVICE] {
            let (vtype, got) = hive
                .element_data(loader, id)
                .expect("read")
                .expect("loader device");
            assert_eq!(vtype, REG_BINARY);
            assert_eq!(got, expected.to_vec());
        }
        let (vtype, got) = hive
            .element_data(loader, ELEMENT_LOCALE)
            .expect("read")
            .expect("12000005");
        assert_eq!(vtype, REG_SZ);
        assert_eq!(decode_sz(&got).expect("locale"), "en-us");
        let (vtype, got) = hive
            .element_data(loader, ELEMENT_25000020)
            .expect("read")
            .expect("25000020");
        assert_eq!(vtype, REG_BINARY);
        assert_eq!(got, vec![0u8; 8]);
        let (vtype, got) = hive
            .element_data(loader, ELEMENT_250000C2)
            .expect("read")
            .expect("250000c2");
        assert_eq!(vtype, REG_BINARY);
        assert_eq!(got, vec![1, 0, 0, 0, 0, 0, 0, 0]);
        let loader_ids = object_element_ids(&hive, loader);
        assert!(
            !loader_ids.contains(&0x1600_0009),
            "fresh loader must not carry 16000009"
        );
        for id in loader_ids {
            assert!(
                !is_template_element(id),
                "fresh loader must have no class-0x4 element, found {id:#010x}"
            );
        }

        // Fresh resume: 8-byte 25000008 and the data-partition device.
        let (vtype, got) = hive
            .element_data(resume, ELEMENT_25000008)
            .expect("read")
            .expect("25000008");
        assert_eq!(vtype, REG_BINARY);
        assert_eq!(got, vec![1, 0, 0, 0, 0, 0, 0, 0]);
        let (_, got) = hive
            .element_data(resume, ELEMENT_DEVICE)
            .expect("read")
            .expect("resume device");
        assert_eq!(got, expected.to_vec());

        // {memdiag}: ESP device, description, no 1600000B.
        let (_, got) = hive
            .element_data(OBJECT_MEMDIAG, ELEMENT_DEVICE)
            .expect("read")
            .expect("memdiag device");
        assert_eq!(got, partition_device(esp).to_vec());
        let (vtype, got) = hive
            .element_data(OBJECT_MEMDIAG, ELEMENT_DESCRIPTION)
            .expect("read")
            .expect("12000004");
        assert_eq!(vtype, REG_SZ);
        assert_eq!(
            decode_sz(&got).expect("description"),
            "Windows Memory Diagnostic"
        );
        assert!(
            !object_element_ids(&hive, OBJECT_MEMDIAG).contains(&ELEMENT_1600000B),
            "memdiag must drop 1600000B"
        );
    }

    /// BIOS BCD parity: the BIOS store clones the `...123457` loader and
    /// resume (distinct from UEFI's `...123456`), `{bootmgr}` carries its
    /// own `11000001` partition device, and the fresh loader carries the
    /// same required elements — `11000001`/`21000001` devices and the
    /// `12000004` description — with the same description value as a UEFI
    /// store built from an otherwise identical request. Class-0x4 setup
    /// elements are stripped on both.
    #[test]
    fn bios_bcd_has_parity_with_uefi_bcd() {
        let data = DeviceIdentity::Mbr {
            disk_signature: [0xDE, 0xAD, 0xBE, 0xEF],
            partition_start_bytes: 1_048_576,
        };
        // On BIOS the ESP identity is not used (bootmgr device = data
        // partition); we pass the same value to satisfy the type.
        let request = StoreRequest {
            firmware: Firmware::Bios,
            identity: data,
            esp_identity: data,
            description: Some("Windows 11 BIOS"),
        };
        let template = template_fixture();
        let out = build(&template, &request).expect("BIOS build must succeed");
        assert_tiling(&out);
        let hive = Hive::parse(&out).expect("BIOS output must re-parse");

        // Loader and resume GUIDs must be the BIOS variants, distinct
        // from UEFI so both stores can coexist.
        let loader = default_object(Firmware::Bios);
        let resume = default_resume_object(Firmware::Bios);
        assert_eq!(loader, OS_LOADER_BIOS);
        assert_eq!(resume, RESUME_BIOS);
        assert_ne!(loader, OS_LOADER_UEFI, "BIOS loader must differ from UEFI");
        assert_ne!(resume, RESUME_UEFI, "BIOS resume must differ from UEFI");

        // {bootmgr} must carry its own 11000001 partition device pointing
        // at the data/system partition (BIOS path uses data identity).
        let (vtype, got) = hive
            .element_data(OBJECT_BOOTMGR, ELEMENT_DEVICE)
            .expect("read")
            .expect("{bootmgr} must have 11000001 on BIOS");
        assert_eq!(vtype, REG_BINARY);
        assert_eq!(
            got,
            partition_device(data).to_vec(),
            "{{bootmgr}} device must equal the data-partition identity"
        );

        // {bootmgr} must point its 23000003 at the BIOS loader.
        let (vtype, got) = hive
            .element_data(OBJECT_BOOTMGR, ELEMENT_DEFAULT_OBJECT)
            .expect("read")
            .expect("{bootmgr} 23000003");
        assert_eq!(vtype, REG_SZ);
        assert_eq!(decode_sz(&got).expect("guid"), loader);

        // Fresh BIOS loader: both partition devices (11000001 and
        // 21000001) must be present and encode the data partition.
        let expected_device = partition_device(data);
        for id in [ELEMENT_DEVICE, ELEMENT_OS_DEVICE] {
            let (vtype, got) = hive
                .element_data(loader, id)
                .expect("read")
                .expect("BIOS loader must carry both partition devices");
            assert_eq!(vtype, REG_BINARY);
            assert_eq!(got, expected_device.to_vec());
        }

        // Fresh BIOS loader: 12000004 (description) must be set.
        let (vtype, got) = hive
            .element_data(loader, ELEMENT_DESCRIPTION)
            .expect("read")
            .expect("BIOS loader must carry 12000004 description");
        assert_eq!(vtype, REG_SZ);
        let bios_description = decode_sz(&got).expect("description");
        assert_eq!(
            bios_description, "Windows 11 BIOS",
            "BIOS loader description must match the request"
        );

        // No class-0x4 template elements on the BIOS loader.
        for id in object_element_ids(&hive, loader) {
            assert!(
                !is_template_element(id),
                "BIOS loader must have no class-0x4 element, found {id:#010x}"
            );
        }

        // Fresh resume must carry a device element.
        let (_, got) = hive
            .element_data(resume, ELEMENT_DEVICE)
            .expect("read")
            .expect("BIOS resume must have 11000001");
        assert_eq!(got, partition_device(data).to_vec());

        // Parity: build a UEFI store from an otherwise identical request
        // (same identity, esp_identity and description; only firmware
        // differs) and compare the required element set and the
        // description on the two fresh loaders.
        let uefi_request = StoreRequest {
            firmware: Firmware::Uefi,
            ..request
        };
        let uefi_out = build(&template, &uefi_request).expect("UEFI build must succeed");
        let uefi_hive = Hive::parse(&uefi_out).expect("UEFI output must re-parse");
        let uefi_loader = default_object(Firmware::Uefi);

        let required = [ELEMENT_DEVICE, ELEMENT_OS_DEVICE, ELEMENT_DESCRIPTION];
        let bios_ids = object_element_ids(&hive, loader);
        let uefi_ids = object_element_ids(&uefi_hive, uefi_loader);
        let bios_required: Vec<u32> = required
            .iter()
            .copied()
            .filter(|id| bios_ids.contains(id))
            .collect();
        let uefi_required: Vec<u32> = required
            .iter()
            .copied()
            .filter(|id| uefi_ids.contains(id))
            .collect();
        assert_eq!(
            bios_required, uefi_required,
            "BIOS and UEFI loaders must carry the same required elements"
        );
        assert_eq!(
            bios_required,
            required.to_vec(),
            "both loaders must carry every required element"
        );

        let (_, uefi_desc) = uefi_hive
            .element_data(uefi_loader, ELEMENT_DESCRIPTION)
            .expect("read")
            .expect("UEFI loader must carry 12000004 description");
        assert_eq!(
            decode_sz(&uefi_desc).expect("description"),
            bios_description,
            "BIOS and UEFI loaders must carry the same description"
        );
    }

    // -- Locale and fallback-object hardening (S22-T1) ------------------

    fn uefi_request(description: Option<&str>) -> StoreRequest<'_> {
        let identity = DeviceIdentity::Gpt {
            disk_guid: [1u8; 16],
            partition_guid: [2u8; 16],
        };
        StoreRequest {
            firmware: Firmware::Uefi,
            identity,
            esp_identity: identity,
            description,
        }
    }

    /// Add a `12000005` locale element to `{bootmgr}` of the standard
    /// fixture, for locale-detection tests.
    fn template_with_bootmgr_locale(locale: &str) -> Vec<u8> {
        let mut hive = Hive::parse(&template_fixture()).expect("fixture parses");
        let objects = hive
            .find_child(hive.root(), b"Objects")
            .expect("find")
            .expect("objects");
        let bootmgr = hive
            .find_child(objects, OBJECT_BOOTMGR.as_bytes())
            .expect("find")
            .expect("bootmgr");
        let elements = hive
            .find_child(bootmgr, b"Elements")
            .expect("find")
            .expect("bootmgr elements");
        add_element(&mut hive, elements, "12000005", REG_SZ, &utf16_nul(locale));
        hive.update_checksum().expect("checksum");
        hive.into_bytes()
    }

    /// Locale values on the four active objects of a built store.
    fn built_locales(bytes: &[u8], firmware: Firmware) -> [String; 4] {
        let hive = Hive::parse(bytes).expect("built store must re-parse");
        [
            OBJECT_BOOTMGR,
            default_object(firmware),
            default_resume_object(firmware),
            OBJECT_MEMDIAG,
        ]
        .map(|object| {
            let (_, data) = hive
                .element_data(object, ELEMENT_LOCALE)
                .expect("read locale")
                .expect("built object must carry a locale element");
            decode_sz(&data).expect("locale text")
        })
    }

    #[test]
    fn locale_in_template_reads_valid_tags_and_refuses_invalid_ones() {
        assert_eq!(
            locale_in_template(&template_with_bootmgr_locale("de-DE")).as_deref(),
            Some("de-DE"),
            "a valid de-DE tag on bootmgr must be returned"
        );
        assert_eq!(
            locale_in_template(&template_fixture()).as_deref(),
            None,
            "a fixture with no locale element must detect nothing"
        );
        assert_eq!(
            locale_in_template(&template_with_bootmgr_locale("../evil")).as_deref(),
            None,
            "an invalid tag must never be returned"
        );
        assert_eq!(locale_in_template(b"not a hive").as_deref(), None);
    }

    #[test]
    fn build_with_locale_writes_the_locale_to_all_four_objects() {
        let template = template_fixture();
        let request = uefi_request(Some("Windows 11 Pro"));

        let explicit = build_with_locale(&template, &request, Some("de-DE"))
            .expect("explicit de-DE locale must build");
        assert_eq!(built_locales(&explicit, Firmware::Uefi), ["de-DE"; 4]);

        // `build` still writes en-us when the template has no detectable
        // locale, and propagates a valid one when the template carries it.
        let default = build(&template, &request).expect("default build must succeed");
        assert_eq!(built_locales(&default, Firmware::Uefi), ["en-us"; 4]);
        let templated = template_with_bootmgr_locale("fr-FR");
        let detected = build(&templated, &request).expect("templated locale must build");
        assert_eq!(built_locales(&detected, Firmware::Uefi), ["fr-FR"; 4]);
    }

    #[test]
    fn build_with_locale_refuses_an_invalid_supplied_locale() {
        let template = template_fixture();
        let request = uefi_request(None);
        for bad in ["../evil", "e", "english", "en-", "en-x"] {
            let err = build_with_locale(&template, &request, Some(bad))
                .expect_err("invalid locale must refuse");
            assert!(
                matches!(err, CoreError::InvalidInput { .. }),
                "must be InvalidInput, got {err}"
            );
            assert!(err.to_string().contains(bad), "must name {bad}: {err}");
        }
    }

    const CUSTOM_LOADER_GUID: &str = "{1a2b3c4d-1111-2222-3333-444455556666}";
    const CUSTOM_RESUME_GUID: &str = "{1a2b3c4d-7777-8888-9999-000011112222}";
    const DANGLING_RESUME_GUID: &str = "{1a2b3c4d-aaaa-bbbb-cccc-ddddeeeeffff}";

    /// A template whose loader and resume use non-default GUIDs and carry
    /// `Description\Type` DWORDs instead of the pinned 24H2 GUIDs, so a
    /// build can only succeed through the type-based fallback. Note the
    /// fixture writes the two `OBJECT_TYPE_*` constants into its own
    /// cells, so it proves the fallback wiring but not the constants'
    /// values; `real_template_builds_both_variants` confirms those
    /// against a real template when one is supplied.
    fn custom_guid_template() -> Vec<u8> {
        custom_guid_template_with_resume_ref(CUSTOM_RESUME_GUID)
    }

    /// `resume_ref` is what the loader's `23000003` names. Passing a GUID
    /// that is absent from `Objects` forces the resume type fallback.
    fn custom_guid_template_with_resume_ref(resume_ref: &str) -> Vec<u8> {
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
        add_element(
            &mut hive,
            bootmgr_el,
            "12000002",
            REG_SZ,
            &utf16_nul("\\EFI\\Microsoft\\Boot\\bootmgfw.efi"),
        );

        let loader = add_key(&mut hive, objects, CUSTOM_LOADER_GUID.as_bytes());
        let loader_desc = add_key(&mut hive, loader, b"Description");
        hive.add_value(
            loader_desc,
            b"Type",
            REG_DWORD,
            &OBJECT_TYPE_OS_LOADER.to_le_bytes(),
        )
        .expect("loader Type must allocate");
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
        add_element(
            &mut hive,
            loader_el,
            "23000003",
            REG_SZ,
            &utf16_nul(resume_ref),
        );

        let resume = add_key(&mut hive, objects, CUSTOM_RESUME_GUID.as_bytes());
        let resume_desc = add_key(&mut hive, resume, b"Description");
        hive.add_value(
            resume_desc,
            b"Type",
            REG_DWORD,
            &OBJECT_TYPE_RESUME.to_le_bytes(),
        )
        .expect("resume Type must allocate");
        let resume_el = add_key(&mut hive, resume, b"Elements");
        add_element(
            &mut hive,
            resume_el,
            "42000002",
            REG_SZ,
            &utf16_nul("\\system32\\winresume.efi"),
        );

        let memdiag = add_key(&mut hive, objects, OBJECT_MEMDIAG.as_bytes());
        let memdiag_el = add_key(&mut hive, memdiag, b"Elements");
        add_element(
            &mut hive,
            memdiag_el,
            "12000002",
            REG_SZ,
            &utf16_nul("\\EFI\\Microsoft\\Boot\\memtest.efi"),
        );

        hive.update_checksum().expect("checksum");
        hive.into_bytes()
    }

    #[test]
    fn build_uses_the_type_fallback_for_non_default_template_guids() {
        let template = custom_guid_template();
        let request = uefi_request(Some("Windows 11 Pro"));
        let out = build(&template, &request).expect("custom GUID template must build");
        let hive = Hive::parse(&out).expect("built store must re-parse");
        let objects = hive
            .find_child(hive.root(), b"Objects")
            .expect("find")
            .expect("objects");

        // The custom objects were cloned from, but the fresh objects keep
        // the standard bcdboot GUIDs and carry the required elements.
        for guid in [OS_LOADER_UEFI, RESUME_UEFI] {
            assert!(
                hive.find_child(objects, guid.as_bytes())
                    .expect("find")
                    .is_some(),
                "fresh object must use the standard GUID {guid}"
            );
        }
        let ids = object_element_ids(&hive, OS_LOADER_UEFI);
        for id in [ELEMENT_DESCRIPTION, ELEMENT_DEVICE, ELEMENT_OS_DEVICE] {
            assert!(ids.contains(&id), "fresh loader must carry {id:#010x}");
        }
        let (_, default) = hive
            .element_data(OBJECT_BOOTMGR, ELEMENT_DEFAULT_OBJECT)
            .expect("read")
            .expect("bootmgr default object");
        assert_eq!(decode_sz(&default).expect("guid text"), OS_LOADER_UEFI);
    }

    /// A 24H2-style template carries other objects with the OS-loader
    /// type (the minimal ntldr loader and the install-media loader).
    /// They sort before a custom loader GUID and carry no usable
    /// `22000002`/`42000002`, so the fallback must skip them rather than
    /// abort with a misleading "carries 42000002 ... expected ..." error.
    #[test]
    fn type_fallback_skips_unusable_loader_candidates() {
        const DECOY_LOADER: &str = "{00000000-0000-0000-0000-000000000001}";
        let mut hive = Hive::parse(&custom_guid_template()).expect("fixture parses");
        let objects = hive
            .find_child(hive.root(), b"Objects")
            .expect("find")
            .expect("objects");
        let decoy = add_key(&mut hive, objects, DECOY_LOADER.as_bytes());
        let description = add_key(&mut hive, decoy, b"Description");
        hive.add_value(
            description,
            b"Type",
            REG_DWORD,
            &OBJECT_TYPE_OS_LOADER.to_le_bytes(),
        )
        .expect("decoy Type must allocate");
        add_key(&mut hive, decoy, b"Elements"); // no 22000002 / 42000002
        hive.update_checksum().expect("checksum");

        let out = build(&hive.into_bytes(), &uefi_request(None))
            .expect("a decoy must not hide a valid loader candidate");
        let built = Hive::parse(&out).expect("built store must re-parse");
        assert!(
            built
                .find_child(built.root(), b"Objects")
                .expect("find")
                .is_some()
        );
        let ids = object_element_ids(&built, OS_LOADER_UEFI);
        assert!(
            ids.contains(&ELEMENT_PATH),
            "real winload path must land on the fresh loader"
        );
        let (_, data) = built
            .element_data(OS_LOADER_UEFI, ELEMENT_PATH)
            .expect("read path")
            .expect("12000002 must exist");
        assert_eq!(
            decode_sz(&data).expect("path text"),
            winload_full_path(Firmware::Uefi)
        );
    }

    /// The resume fallback is reached when the loader's `23000003` names a
    /// GUID absent from `Objects`: a resume-type object elsewhere must
    /// still be cloned into the fresh resume object.
    #[test]
    fn build_uses_the_type_fallback_for_a_dangling_resume_reference() {
        let template = custom_guid_template_with_resume_ref(DANGLING_RESUME_GUID);
        assert!(!template.is_empty());
        let out = build(&template, &uefi_request(None))
            .expect("dangling resume ref must fall back to the resume type");
        let hive = Hive::parse(&out).expect("built store must re-parse");
        let objects = hive
            .find_child(hive.root(), b"Objects")
            .expect("find")
            .expect("objects");
        assert!(
            hive.find_child(objects, RESUME_UEFI.as_bytes())
                .expect("find")
                .is_some(),
            "the fresh resume object must exist even though the template ref dangled"
        );
        let (_, resume) = hive
            .element_data(OBJECT_BOOTMGR, ELEMENT_RESUME_OBJECT)
            .expect("read")
            .expect("bootmgr resume object");
        assert_eq!(decode_sz(&resume).expect("guid text"), RESUME_UEFI);
    }

    /// Pin the two user-visible "missing object" strings so a future
    /// fallback refactor cannot silently replace them with an internal
    /// error or a wrong GUID.
    #[test]
    fn build_pins_missing_loader_and_resume_messages() {
        // No loader object and no loader-type object: the fixed GUID's
        // message names TEMPLATE_LOADER_B012.
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
        hive.update_checksum().expect("checksum");
        let err = build(&hive.into_bytes(), &uefi_request(None))
            .expect_err("a template without a loader must refuse");
        assert_eq!(
            err.to_string(),
            format!(
                "invalid input: bcd template is missing the UEFI loader object {TEMPLATE_LOADER_B012}"
            )
        );

        // A valid loader naming a dangling GUID, with the resume-type
        // object removed: the message preserves the dangling GUID.
        let mut hive = Hive::parse(&custom_guid_template_with_resume_ref(DANGLING_RESUME_GUID))
            .expect("fixture parses");
        let objects = hive
            .find_child(hive.root(), b"Objects")
            .expect("find")
            .expect("objects");
        assert!(
            hive.remove_child(objects, CUSTOM_RESUME_GUID.as_bytes())
                .expect("remove resume")
        );
        hive.update_checksum().expect("checksum");
        let err = build(&hive.into_bytes(), &uefi_request(None))
            .expect_err("a template without a resume object must refuse");
        assert_eq!(
            err.to_string(),
            format!(
                "invalid input: bcd template is missing the resume object {DANGLING_RESUME_GUID}"
            )
        );
    }

    /// A crafted `Objects` subkey count must never drive the type-scan
    /// loop. `regf::find_child` refuses the count/list mismatch before
    /// the fallback is consulted (so `build` fails promptly at the
    /// bootmgr lookup), and the fallback itself returns `Ok(None)` at
    /// once instead of iterating 0..0xFFFF_FFFF.
    #[test]
    fn objects_count_mismatch_refuses_promptly() {
        let mut hive = Hive::parse(&template_fixture()).expect("fixture parses");
        let objects = hive
            .find_child(hive.root(), b"Objects")
            .expect("find")
            .expect("objects");
        let count_at = Hive::cell_file(objects, "forged count").expect("cell") + 4 + 0x14;
        hive.store_u32(count_at, u32::MAX, "forged object count")
            .expect("patch count");
        hive.update_checksum().expect("checksum");
        let bytes = hive.into_bytes();

        assert_eq!(
            locale_in_template(&bytes),
            None,
            "locale detection must not scan a forged count"
        );

        let probe = Hive::parse(&bytes).expect("mismatch hive still parses");
        let objects = probe
            .find_child(probe.root(), b"Objects")
            .expect("find")
            .expect("objects");
        assert!(
            matches!(
                find_template_object(
                    &probe,
                    objects,
                    TEMPLATE_LOADER_B012,
                    OBJECT_TYPE_OS_LOADER,
                    |_, _| true,
                ),
                Ok(None)
            ),
            "the guarded scan must refuse a count/list mismatch at once"
        );

        let err = build(&bytes, &uefi_request(None)).expect_err("mismatch hive must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "must be InvalidInput, got {err}"
        );
    }
}
