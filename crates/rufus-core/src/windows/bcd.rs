//! BCD store facts and the slice-5 decision (S21, slice 5 of 12).
//!
//! This module is a decision-and-facts record, not an implementation:
//! it owns no editor, performs no I/O, and parses nothing. Slice 6
//! builds the small in-crate `regf` patcher against the constants and
//! the plan recorded here.
//!
//! Question: after the image is applied, the USB needs boot entries
//! pointing at the applied Windows — a Boot Configuration Data store
//! on the ESP (UEFI) and on the data partition (BIOS) — the way real
//! Rufus leaves them.
//!
//! What real Rufus does: it runs the *applied image's own* tools,
//! recovered from the decompiled `wue.c` (function `0x140066ea0` —
//! see `example/decompiled/functions/0x140066ea0.c`, `// address:
//! 0x140066ea0`):
//! `bcdboot.exe /bootex /offline /f ALL /s <ESP>` followed by
//! `bcdedit.exe /store <ESP>\EFI\Microsoft\Boot\BCD /set {default}
//! recoveryenabled no`. On Linux that path needs Wine (about 500 MiB,
//! not installed on this host), so a host-side implementation is
//! needed.
//!
//! Evidence: the Windows 11 Enterprise Evaluation 24H2 ISO was mounted
//! read-only (`mount -t udf -o loop,ro`) and `sources/boot.wim` image 1
//! was extracted with `wimlib-imagex extract`. The image holds, among
//! others, `Windows/System32/config/BCD-Template` (20 480 bytes, a real
//! `regf` hive whose root key is `System` with an `Objects` key holding
//! 12 subkeys), its own `Windows/System32/bcdboot.exe` and
//! `bcdedit.exe`, the install-media stores `Windows/Boot/DVD/EFI/BCD`
//! and `Windows/Boot/DVD/PCAT/BCD`, and `Windows/Boot/EFI/bootmgr.efi`.
//!
//! The template's 12 objects, summarised (seven match the well-known
//! identifiers below; five are template-only loaders): `{bootmgr}`
//! carries path, description, locale, display order, default object,
//! timeout and flags; `{memdiag}` carries path, locale, display order,
//! `1600000B`, flags (`45000001`) and a binary blob (`47000005`); `{emssettings}`, `{hypervisorsettings}`,
//! `{bootloadersettings}` and `{globalsettings}` carry one element each
//! (`16000020`, `15000011`, and `14000006` twice); `{legacy}` carries
//! `250000F3/F4/F5`. The five template-only loaders are one minimal
//! loader (`12000002`, `45000001`, `47000005` only) plus four full
//! loaders on the locale/display-order/os-locate-path/loader-path
//! shape with `45000001` and a `47000005` binary blob
//! (9 to 11 elements each, varying in `16000060` and `42000003`
//! presence — the exact per-object sets live in the spike record and
//! slice 6 reads the template live rather than trusting any summary).
//! Critical facts: no object in the template carries a `11000001` or
//! `21000001` binary device element — that is exactly what `bcdboot`
//! adds per machine — and the loaders give their OS device as the
//! string `\windows` under `22000002` (a locate-by-path device). The
//! ISO's own install-media stores (`\boot\bcd` for BIOS,
//! `\efi\microsoft\boot\bcd` for UEFI) already boot Setup and are copied
//! verbatim; they need no work.
//!
//! Candidates:
//! a. Write a store from scratch — rejected: the template already holds
//!    every object and element a boot needs except the two per-machine
//!    device elements, so generating a hive buys nothing.
//! b. Ship the applied image's own `BCD-Template` and patch it with a
//!    small in-crate `regf` editor — kept: minimal new code, no
//!    dependency, and the template locates Windows by path, so the
//!    patched store needs no GPT GUID and no MBR signature or offset,
//!    which also keeps a To Go store portable.
//! c. Run the image's `bcdboot`/`bcdedit` under Wine — rejected: Wine
//!    is heavy, needs the user's permission, is untested on this host,
//!    and PLAN calls it the last resort.
//!
//! Decision: candidate (b). Slice 6 implements the patcher; this module
//! only pins the identifiers, element ids, and paths it will use.
//!
//! Slice-6 plan (recorded, not implemented): the UEFI store at
//! [`UEFI_STORE_PATH`] gets `{bootmgr}` with `11000001` (boot device)
//! and `12000002` set to `\EFI\Microsoft\Boot\bootmgfw.efi`,
//! `23000003` pointing at the chosen loader, and the loader getting its
//! device element and `12000004` description (the edition). The
//! template pairs `22000002` = `\windows` with `42000002` =
//! `\system32\winload.efi`, so writing `\windows\system32\winload.efi`
//! into `42000002` would double the system root: which store gets which
//! loader path, and whether slice 6 rewrites `42000002` or keeps the
//! template value, is to be confirmed by slice 6 against a live
//! template read. The BIOS store at [`BIOS_STORE_PATH`] takes the same
//! shape with `\bootmgr` (and the `winload.exe` counterpart, likewise
//! to be confirmed). The editing primitive adds a `vk`
//! cell plus a value-list cell (plus a data cell when the value is not
//! inline) to an existing `nk` and updates `nval`/`vals`, inside the
//! template's free space; existing same-or-shorter string values can be
//! overwritten in place.
//!
//! Naming honesty: the template-only loaders are named by GUID prefix
//! ([`TEMPLATE_LOADER_466F`] etc.) because the evidence does not prove
//! which loader is the EFI, BIOS, or PE one — slice 6 must identify the
//! loader to patch by reading its elements (for example the `42000002`
//! suffix, `winload.efi` versus `winload.exe`), never by trusting a
//! name. Element constants carry the observed role where the template
//! gives one (`ELEMENT_TIMEOUT`) and bare hex names where it does not
//! (`ELEMENT_16000060`), so no name invents a meaning.
//!
//! Limitations, stated plainly: no Windows image has been booted yet
//! (the host has 7.6 GiB RAM with about 600 MiB free, so QEMU cannot
//! run Windows now); boot acceptance is slices 10-11. The template
//! above is from Windows 11 24H2; the Windows 10 template has not been
//! inspected, so slice 6 must confirm these identifiers there before
//! relying on them.
//!
//! Not here yet: the `regf` patcher itself (slice 6), pipeline wiring,
//! and Windows To Go.

/// `{bootmgr}`: the boot manager object both stores patch.
pub const OBJECT_BOOTMGR: &str = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}";

/// `{memdiag}`: the memory-diagnostic object, carried over untouched.
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
/// `12000002`, `45000001` and `47000005`. Role unknown (see the module
/// docs); slice 6 identifies loaders by their elements, not by name.
pub const TEMPLATE_LOADER_466F: &str = "{466f5a88-0af2-4f76-9038-095b170dc21c}";

/// Template-only full loader (`7254a080-...`). Role unknown (see the
/// module docs); slice 6 identifies loaders by their elements.
pub const TEMPLATE_LOADER_7254: &str = "{7254a080-1510-4e85-ac0f-e7fb3d444736}";

/// Template-only full loader (`a1943bbc-...`). Role unknown (see the
/// module docs); slice 6 identifies loaders by their elements.
pub const TEMPLATE_LOADER_A194: &str = "{a1943bbc-ea85-487c-97c7-c9ede908a38a}";

/// Template-only full loader (`b012b84d-...`). Role unknown (see the
/// module docs); slice 6 identifies loaders by their elements.
pub const TEMPLATE_LOADER_B012: &str = "{b012b84d-c47c-4ed5-b722-c0c42163e569}";

/// Template-only full loader (`cbd971bf-...`). Role unknown (see the
/// module docs); slice 6 identifies loaders by their elements.
pub const TEMPLATE_LOADER_CBD9: &str = "{cbd971bf-b7b8-4885-951a-fa03044f5d71}";

/// `0x11000001` (class `0x11`, device): the boot-device element
/// `bcdboot` adds to `{bootmgr}` per machine; absent from the template.
pub const ELEMENT_DEVICE: u32 = 0x1100_0001;

/// `0x21000001` (class `0x21`, device): the os-device element `bcdboot`
/// adds to the chosen loader per machine; absent from the template.
pub const ELEMENT_OS_DEVICE: u32 = 0x2100_0001;

/// `0x22000002` (class `0x22`, string): the os device the template
/// loaders carry as a locate-by-path string (`REG_SZ` `\windows`).
pub const ELEMENT_OS_LOCATE_PATH: u32 = 0x2200_0002;

/// `0x23000003` (class `0x23`): the default-object element on
/// `{bootmgr}` pointing at the chosen loader. Its value encoding was
/// not recorded in the spike; slice 6 confirms it against a live read.
pub const ELEMENT_DEFAULT_OBJECT: u32 = 0x2300_0003;

/// `0x12000002` (class `0x12`, string): the path element — the boot
/// application path on `{bootmgr}` (`bootmgfw.efi` / `bootmgr`) and on
/// the minimal template loader.
pub const ELEMENT_PATH: u32 = 0x1200_0002;

/// `0x12000004` (class `0x12`, string): the description element; slice 6
/// sets it to the edition on the chosen loader.
pub const ELEMENT_DESCRIPTION: u32 = 0x1200_0004;

/// `0x12000005` (class `0x12`, string): the locale element.
pub const ELEMENT_LOCALE: u32 = 0x1200_0005;

/// `0x14000006` (class `0x14`, list): the display-order element.
pub const ELEMENT_DISPLAY_ORDER: u32 = 0x1400_0006;

/// `0x25000004` (class `0x25`, integer): the timeout element on
/// `{bootmgr}`.
pub const ELEMENT_TIMEOUT: u32 = 0x2500_0004;

/// `0x42000002` (class `0x42`, file path): the loader path element;
/// the template pairs it as `\system32\winload.efi` next to
/// `22000002` = `\windows` (see the slice-6 plan for what slice 6 must
/// confirm before rewriting it).
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

/// `0x16000060` (class `0x16`, integer/boolean): present on some
/// template loaders; no finer role observed.
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

/// `0x45000001` (class `0x45`, flags): carried by nearly every template
/// object; no finer role observed.
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
/// them): the UEFI BCD slice 6 patches.
pub const UEFI_STORE_PATH: &str = "\\EFI\\Microsoft\\Boot\\BCD";

/// Target store path on the data partition (backslashes as the boot
/// manager sees them): the BIOS BCD slice 6 patches.
pub const BIOS_STORE_PATH: &str = "\\boot\\bcd";

/// The element class of `id`: the top byte (`id >> 24`).
///
/// The top nibble alone cannot be the class: `0x11000001` (device) and
/// `0x12000002` (string) would collide at `0x1`, yet the template uses
/// them for different kinds. The full top byte keeps them apart,
/// restated from the value types the extracted template actually
/// holds: `0x11` device (added by `bcdboot`; absent from the template),
/// `0x12` string, `0x14` list, `0x15` integer (one byte observed),
/// `0x16` integer-or-boolean, `0x17` integer-or-boolean, `0x21` device
/// (added by `bcdboot`; absent from the template), `0x22` string
/// (observed `REG_SZ`), `0x23` default object (value encoding not
/// recorded in the spike; slice 6 confirms it against a live read),
/// `0x25` integer, `0x26` boolean (one byte observed), `0x31` device
/// path and `0x32` ramdisk options (seen in the install-media stores,
/// not the template), `0x42` file path, `0x45` flags, `0x47` binary
/// (16 bytes observed).
#[must_use]
pub fn element_class(id: u32) -> u8 {
    // A shift, not an index: no failure mode, no panic path.
    (id >> 24) as u8
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
        let table: [(u32, u32, u8); 24] = [
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
        // shared mixed-endian formatter must equal the constant slice 6
        // patches against.
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
}
