//! DOS locale planning: keyboard, codepage and EGA selection plus the
//! byte-exact `CONFIG.SYS` / `AUTOEXEC.BAT` contents.
//!
//! This mirrors upstream `src/dos_locale.c` (byte-identical at the `v4.15`
//! tag), i.e. `SetDOSLocale` (`FUN_1400073e0`, 2742 bytes) and its helper
//! family (`example/functions.csv` `dos_locale` rows `0x1400050a0` through
//! `0x140006b50`: the `ms`/`fd_get_kbdrv` matchers, the human-readable
//! tables, `get_kb`, the EGA pickers and the codepage upgrade). Table
//! order and every entry below follow that file line by line:
//! `ms_kb1..4` / `fd_kb1..4` (`dos_locale.c:133-164`), `kbdrv_data`
//! (`:171-176`), `kb_hr_list` (`:227-286`), `cp_hr_list` (`:308-424`),
//! the `get_kb()` case list (`:469-689`), `ms_get_ega` (`:790-820`),
//! `fd_get_ega` (`:824-952`), `fd_upgrade_cp` (`:956-963`) and the
//! `CONFIG.SYS` / `AUTOEXEC.BAT` writers (`:966-1072`).
//!
//! The one deliberate difference is the host-locale input. Upstream reads
//! `GetKeyboardLayoutNameA`, `GetOEMCP` and `GetLocaleInfoA` behind the
//! caller's back; this module never calls a Windows API. The caller
//! supplies the Windows-equivalent values up front as a [`Locale`]
//! (keyboard id, system language id, OEM codepage), so [`plan`] is a pure
//! function of `(flavor, locale)`. A caller whose OEM codepage is UTF-8
//! (65001) must resolve the real system codepage itself — upstream does
//! that lookup inside `SetDOSLocale`, here there is nothing to call.
//!
//! This module writes nothing: [`plan`] returns the file bytes and the
//! reference log lines for the caller to use. Placing these files onto a
//! stick belongs to the FreeDOS install slice (5/8) and the wiring slice
//! (7/8).
//!
//! Line endings are LF (`\n`) throughout, exactly as the C `fprintf`
//! calls emit them — DOS reads that fine and byte fidelity matters more
//! than convention here.

/// Which DOS family the locale is planned for: the EGA file set, the
/// keyboard-driver membership lists and the codepage upgrade all differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DosFlavor {
    /// WinME DOS (`ms_get_kbdrv`, `ms_get_ega`, no codepage upgrade).
    MsDos,
    /// FreeDOS (`fd_get_kbdrv`, `fd_get_ega`, 850 upgraded to 858).
    FreeDos,
}

/// Which `KEYBOARD.SYS`-family driver serves a keyboard code, in the
/// order `ms_get_kbdrv` / `fd_get_kbdrv` search (`dos_locale.c:197-221`):
/// the first list holding the code wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardDriver {
    /// `keyboard.sys`, default codepage 437 (`kbdrv_data[0]`).
    KeyboardSys,
    /// `keybrd2.sys`, default codepage 850 (`kbdrv_data[1]`).
    Keybrd2,
    /// `keybrd3.sys`, default codepage 850 (`kbdrv_data[2]`).
    Keybrd3,
    /// `keybrd4.sys`, default codepage 853 (`kbdrv_data[3]`).
    Keybrd4,
}

impl KeyboardDriver {
    /// The driver file name written into `AUTOEXEC.BAT` (`kbdrv_data`
    /// names, `dos_locale.c:171-176`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::KeyboardSys => "keyboard.sys",
            Self::Keybrd2 => "keybrd2.sys",
            Self::Keybrd3 => "keybrd3.sys",
            Self::Keybrd4 => "keybrd4.sys",
        }
    }

    /// The fallback codepage when no EGA file holds the requested one
    /// (`kbdrv_data` default codepages, `dos_locale.c:171-176`).
    #[must_use]
    pub fn default_codepage(self) -> u32 {
        match self {
            Self::KeyboardSys => 437,
            Self::Keybrd2 => 850,
            Self::Keybrd3 => 850,
            Self::Keybrd4 => 853,
        }
    }
}

/// WinME DOS `KEYBOARD.SYS` codes (`ms_kb1`, `dos_locale.c:133-136`).
pub const MS_KB1: &[&str] = &[
    "be", "br", "cf", "cz", "dk", "fr", "gr", "hu", "it", "la", "nl", "no", "pl", "po", "sf", "sg",
    "sl", "sp", "su", "sv", "uk", "us", "yu",
];

/// WinME DOS `KEYBRD2.SYS` codes (`ms_kb2`, `dos_locale.c:137-140`).
pub const MS_KB2: &[&str] = &[
    "bg", "br", "cf", "cz", "gk", "gr", "hu", "is", "it", "no", "pl", "ro", "ru", "sl", "su", "sv",
    "tr", "uk", "us", "yc", "yu",
];

/// WinME DOS `KEYBRD3.SYS` codes (`ms_kb3`, `dos_locale.c:141-144`).
pub const MS_KB3: &[&str] = &[
    "be", "bl", "cz", "dk", "fr", "gr", "hu", "it", "nl", "pl", "ru", "sf", "sg", "sl", "sp", "su",
    "sv", "uk", "ur", "us", "yu",
];

/// WinME DOS `KEYBRD4.SYS` codes (`ms_kb4`, `dos_locale.c:145-146`).
pub const MS_KB4: &[&str] = &["ar", "et", "gk", "he", "pl", "us"];

/// FreeDOS `KEYBOARD.SYS` codes (`fd_kb1`, `dos_locale.c:152-155`).
pub const FD_KB1: &[&str] = &[
    "be", "br", "cf", "co", "cz", "dk", "dv", "fr", "gr", "hu", "it", "jp", "la", "lh", "nl", "no",
    "pl", "po", "rh", "sf", "sg", "sk", "sp", "su", "sv", "uk", "us", "yu",
];

/// FreeDOS `KEYBRD2.SYS` codes (`fd_kb2`, `dos_locale.c:156-157`).
pub const FD_KB2: &[&str] = &["bg", "ce", "gk", "is", "ro", "ru", "rx", "tr", "tt", "yc"];

/// FreeDOS `KEYBRD3.SYS` codes (`fd_kb3`, `dos_locale.c:158-161`).
pub const FD_KB3: &[&str] = &[
    "az", "bl", "et", "fo", "hy", "il", "ka", "kk", "ky", "lt", "lv", "mk", "mn", "mt", "ph", "sq",
    "tj", "tm", "ur", "uz", "vi",
];

/// FreeDOS `KEYBRD4.SYS` codes (`fd_kb4`, `dos_locale.c:162-164`).
pub const FD_KB4: &[&str] = &[
    "ar", "bn", "bx", "fx", "ix", "kx", "ne", "ng", "px", "sx", "ux",
];

/// The per-flavor driver search table behind [`driver_for`]: each driver
/// paired with its membership list, the first pair holding the code wins —
/// the `for (i = 0; ...)` loop of `ms_get_kbdrv` / `fd_get_kbdrv`, with
/// driver and list kept in one pair so the order cannot drift apart.
fn driver_lists(flavor: DosFlavor) -> [(KeyboardDriver, &'static [&'static str]); 4] {
    match flavor {
        DosFlavor::MsDos => [
            (KeyboardDriver::KeyboardSys, MS_KB1),
            (KeyboardDriver::Keybrd2, MS_KB2),
            (KeyboardDriver::Keybrd3, MS_KB3),
            (KeyboardDriver::Keybrd4, MS_KB4),
        ],
        DosFlavor::FreeDos => [
            (KeyboardDriver::KeyboardSys, FD_KB1),
            (KeyboardDriver::Keybrd2, FD_KB2),
            (KeyboardDriver::Keybrd3, FD_KB3),
            (KeyboardDriver::Keybrd4, FD_KB4),
        ],
    }
}

/// Which driver serves `keyboard`, porting `ms_get_kbdrv` / `fd_get_kbdrv`
/// (`dos_locale.c:197-221`): the first list holding the code wins, and a
/// code in no list reads as `None` (upstream returns -1).
///
/// The match is an exact ASCII comparison — `safe_strcmp` upstream, `==`
/// here — with no case folding: the codes come from our own
/// [`KEYBOARD_TABLE`], which is already lower case.
#[must_use]
pub fn driver_for(flavor: DosFlavor, keyboard: &str) -> Option<KeyboardDriver> {
    driver_lists(flavor).iter().find_map(|(driver, list)| {
        if list.contains(&keyboard) {
            Some(*driver)
        } else {
            None
        }
    })
}

/// Keyboard code to human-readable name (`kb_hr_list`,
/// `dos_locale.c:227-286`), all 56 entries in reference order. `ko` and
/// `fa` stay absent: both are commented out upstream as unsupported by
/// FreeDOS, and this port invents nothing.
pub const KB_HR_LIST: &[(&str, &str)] = &[
    ("ar", "Arabic"),
    ("bg", "Bulgarian"),
    ("ch", "Chinese"),
    ("cz", "Czech"),
    ("dk", "Danish"),
    ("gr", "German"),
    ("sg", "Swiss-German"),
    ("gk", "Greek"),
    ("us", "US-English"),
    ("uk", "UK-English"),
    ("cf", "CA-French"),
    ("dv", "US-Dvorak"),
    ("lh", "US-Dvorak (LH)"),
    ("rh", "US-Dvorak (RH)"),
    ("sp", "Spanish"),
    ("la", "Latin-American"),
    ("su", "Finnish"),
    ("fr", "French"),
    ("be", "Belgian-French"),
    ("sf", "Swiss-French"),
    ("il", "Hebrew"),
    ("hu", "Hungarian"),
    ("is", "Icelandic"),
    ("it", "Italian"),
    ("jp", "Japanese"),
    ("nl", "Dutch"),
    ("no", "Norwegian"),
    ("pl", "Polish"),
    ("br", "Brazilian"),
    ("po", "Portuguese"),
    ("ro", "Romanian"),
    ("ru", "Russian"),
    ("yu", "YU-Latin"),
    ("yc", "YU-Cyrillic"),
    ("sl", "Slovak"),
    ("sq", "Albanian"),
    ("sv", "Swedish"),
    ("tr", "Turkish"),
    ("ur", "Ukrainian"),
    ("bl", "Belarusian"),
    ("et", "Estonian"),
    ("lv", "Latvian"),
    ("lt", "Lithuanian"),
    ("tj", "Tajik"),
    ("vi", "Vietnamese"),
    ("hy", "Armenian"),
    ("az", "Azeri"),
    ("mk", "Macedonian"),
    ("ka", "Georgian"),
    ("fo", "Faeroese"),
    ("mt", "Maltese"),
    ("kk", "Kazakh"),
    ("ky", "Kyrgyz"),
    ("uz", "Uzbek"),
    ("tm", "Turkmen"),
    ("tt", "Tatar"),
];

/// The human-readable name of a keyboard code (`kb_to_hr`,
/// `dos_locale.c:288-299`). Upstream asserts on a miss; this returns
/// `None` instead — every `get_kb()` result is in the table, so a miss
/// means a caller-supplied code the reference never produces.
#[must_use]
pub fn keyboard_name(code: &str) -> Option<&'static str> {
    KB_HR_LIST
        .iter()
        .find_map(|(id, name)| if *id == code { Some(*name) } else { None })
}

/// Codepage to human-readable name (`cp_hr_list`, `dos_locale.c:308-424`
/// — from the FreeDOS CPX pack and the codepage-identifier list), all 115
/// entries in reference order.
pub const CP_HR_LIST: &[(u32, &str)] = &[
    (113, "Lat-Yugoslavian"),
    (437, "US-English"),
    (667, "Polish"),
    (668, "Polish (Alt)"),
    (708, "Arabic (708)"),
    (709, "Arabic (709)"),
    (710, "Arabic (710)"),
    (720, "Arabic (DOS)"),
    (737, "Greek (DOS)"),
    (770, "Baltic"),
    (771, "Cyr-Russian (KBL)"),
    (772, "Cyr-Russian"),
    (773, "Baltic Rim (Old)"),
    (774, "Lithuanian"),
    (775, "Baltic Rim"),
    (777, "Acc-Lithuanian (Old)"),
    (778, "Acc-Lithuanian"),
    (790, "Mazovian-Polish"),
    (808, "Cyr-Russian (Euro)"),
    (848, "Cyr-Ukrainian (Euro)"),
    (849, "Cyr-Belarusian (Euro)"),
    (850, "Western-European"),
    (851, "Greek"),
    (852, "Central-European"),
    (853, "Southern-European"),
    (855, "Cyr-South-Slavic"),
    (856, "Hebrew II"),
    (857, "Turkish"),
    (858, "Western-European (Euro)"),
    (859, "Western-European (Alt)"),
    (860, "Portuguese"),
    (861, "Icelandic"),
    (862, "Hebrew"),
    (863, "Canadian-French"),
    (864, "Arabic"),
    (865, "Nordic"),
    (866, "Cyr-Russian"),
    (867, "Czech Kamenicky"),
    (869, "Modern Greek"),
    (872, "Cyr-South-Slavic (Euro)"),
    (874, "Thai"),
    (895, "Czech Kamenicky (Alt)"),
    (899, "Armenian"),
    (932, "Japanese"),
    (936, "Chinese (Simplified)"),
    (949, "Korean"),
    (950, "Chinese (Traditional)"),
    (991, "Mazovian-Polish (Zloty)"),
    (1116, "Estonian"),
    (1117, "Latvian"),
    (1118, "Lithuanian"),
    (1119, "Cyr-Russian (Alt)"),
    (1125, "Cyr-Ukrainian"),
    (1131, "Cyr-Belarusian"),
    (1250, "Central European"),
    (1251, "Cyrillic"),
    (1252, "Western European"),
    (1253, "Greek"),
    (1254, "Turkish"),
    (1255, "Hebrew"),
    (1256, "Arabic"),
    (1257, "Baltic"),
    (1258, "Vietnamese"),
    (1361, "Korean"),
    (3012, "Cyr-Latvian"),
    (3021, "Cyr-Bulgarian"),
    (3845, "Hungarian"),
    (3846, "Turkish"),
    (3848, "Brazilian (ABICOMP)"),
    (30000, "Saami"),
    (30001, "Celtic"),
    (30002, "Cyr-Tajik"),
    (30003, "Latin American"),
    (30004, "Greenlandic"),
    (30005, "Nigerian"),
    (30006, "Vietnamese"),
    (30007, "Latin"),
    (30008, "Cyr-Ossetian"),
    (30009, "Romani"),
    (30010, "Cyr-Moldovan"),
    (30011, "Cyr-Chechen"),
    (30012, "Cyr-Siberian"),
    (30013, "Cyr-Turkic"),
    (30014, "Cyr-Finno-Ugric"),
    (30015, "Cyr-Khanty"),
    (30016, "Cyr-Mansi"),
    (30017, "Cyr-Northwestern"),
    (30018, "Lat-Tatar"),
    (30019, "Lat-Chechen"),
    (30020, "Low-Saxon and Frisian"),
    (30021, "Oceanian"),
    (30022, "First Nations"),
    (30023, "Southern African"),
    (30024, "North & East African"),
    (30025, "Western African"),
    (30026, "Central African"),
    (30027, "Beninese"),
    (30028, "Nigerian (Alt)"),
    (30029, "Mexican"),
    (30030, "Mexican (Alt)"),
    (30031, "Northern-European"),
    (30032, "Nordic"),
    (30033, "Crimean-Tatar (Hryvnia)"),
    (30034, "Cherokee"),
    (30039, "Cyr-Ukrainian (Hryvnia)"),
    (30040, "Cyr-Russian (Hryvnia)"),
    (58152, "Cyr-Kazakh (Euro)"),
    (58210, "Cyr-Azeri"),
    (58335, "Kashubian"),
    (59234, "Cyr-Tatar"),
    (59829, "Georgian"),
    (60258, "Lat-Azeri"),
    (60853, "Georgian (Alt)"),
    (62306, "Cyr-Uzbek"),
    (65001, "Unicode (UTF-8)"),
];

/// The human-readable name of a codepage (`cp_to_hr`,
/// `dos_locale.c:426-437`). Upstream asserts on a miss; this returns
/// `None` instead — the OEM codepage is caller-supplied and may be
/// anything, including values with no EGA file and no table row.
#[must_use]
pub fn codepage_name(codepage: u32) -> Option<&'static str> {
    CP_HR_LIST
        .iter()
        .find_map(|(cp, name)| if *cp == codepage { Some(*name) } else { None })
}

/// Keyboard-id to DOS keyboard code: every `case` label of the `get_kb()`
/// switch (`dos_locale.c:469-689`) flattened into one table in reference
/// order, 157 rows. The `#if 0` block (`:691-742`, Thai/Urdu/Sorbian and
/// friends) is left out exactly as upstream leaves it out, and the
/// commented-out `ko` (`:567-569`) and `fa` (`:644-646`) rows stay absent.
pub const KEYBOARD_TABLE: &[(u32, &str)] = &[
    (0x0000_0001, "ar"),
    (0x0001_0401, "ar"),
    (0x0002_0401, "ar"),
    (0x0000_0002, "bg"),
    (0x0000_0402, "bg"),
    (0x0001_0402, "bg"),
    (0x0002_0402, "bg"),
    (0x0003_0402, "bg"),
    (0x0004_0402, "bg"),
    (0x0000_0004, "ch"),
    (0x0000_0404, "ch"),
    (0x0000_0804, "ch"),
    (0x0000_0c04, "ch"),
    (0x0000_1004, "ch"),
    (0x0000_1404, "ch"),
    (0x0000_0005, "cz"),
    (0x0000_0405, "cz"),
    (0x0001_0405, "cz"),
    (0x0002_0405, "cz"),
    (0x0000_0006, "dk"),
    (0x0000_0406, "dk"),
    (0x0000_0007, "gr"),
    (0x0000_0407, "gr"),
    (0x0001_0407, "gr"),
    (0x0000_0807, "sg"),
    (0x0000_0008, "gk"),
    (0x0000_0408, "gk"),
    (0x0001_0408, "gk"),
    (0x0002_0408, "gk"),
    (0x0003_0408, "gk"),
    (0x0004_0408, "gk"),
    (0x0005_0408, "gk"),
    (0x0006_0408, "gk"),
    (0x0000_0009, "us"),
    (0x0000_0409, "us"),
    (0x0002_0409, "us"),
    (0x0005_0409, "us"),
    (0x0000_0809, "uk"),
    (0x0000_0452, "uk"),
    (0x0000_1809, "uk"),
    (0x0001_1809, "uk"),
    (0x0000_0c0c, "cf"),
    (0x0000_1009, "cf"),
    (0x0001_1009, "cf"),
    (0x0001_0409, "dv"),
    (0x0003_0409, "lh"),
    (0x0004_0409, "rh"),
    (0x0000_000a, "sp"),
    (0x0000_040a, "sp"),
    (0x0001_040a, "sp"),
    (0x0000_080a, "la"),
    (0x0000_000b, "su"),
    (0x0000_040b, "su"),
    (0x0001_083b, "su"),
    (0x0000_000c, "fr"),
    (0x0000_040c, "fr"),
    (0x0000_046e, "fr"),
    (0x0000_080c, "be"),
    (0x0001_080c, "be"),
    (0x0000_100c, "sf"),
    (0x0000_000d, "il"),
    (0x0000_040d, "il"),
    (0x0000_000e, "hu"),
    (0x0000_040e, "hu"),
    (0x0001_040e, "hu"),
    (0x0000_000f, "is"),
    (0x0000_040f, "is"),
    (0x0000_0010, "it"),
    (0x0000_0410, "it"),
    (0x0001_0410, "it"),
    (0x0000_0011, "jp"),
    (0x0000_0411, "jp"),
    (0x0000_0013, "nl"),
    (0x0000_0413, "nl"),
    (0x0000_0813, "nl"),
    (0x0000_0014, "no"),
    (0x0000_0414, "no"),
    (0x0000_043b, "no"),
    (0x0001_043b, "no"),
    (0x0000_0015, "pl"),
    (0x0001_0415, "pl"),
    (0x0000_0415, "pl"),
    (0x0000_0016, "br"),
    (0x0000_0416, "br"),
    (0x0001_0416, "br"),
    (0x0000_0816, "po"),
    (0x0000_0018, "ro"),
    (0x0000_0418, "ro"),
    (0x0001_0418, "ro"),
    (0x0002_0418, "ro"),
    (0x0000_0019, "ru"),
    (0x0000_0419, "ru"),
    (0x0001_0419, "ru"),
    (0x0000_001a, "yu"),
    (0x0000_041a, "yu"),
    (0x0000_081a, "yu"),
    (0x0000_0024, "yu"),
    (0x0000_0424, "yu"),
    (0x0000_0c1a, "yc"),
    (0x0000_201a, "yc"),
    (0x0000_001b, "sl"),
    (0x0000_041b, "sl"),
    (0x0001_041b, "sl"),
    (0x0000_001c, "sq"),
    (0x0000_041c, "sq"),
    (0x0000_001d, "sv"),
    (0x0000_041d, "sv"),
    (0x0000_083b, "sv"),
    (0x0000_001f, "tr"),
    (0x0000_041f, "tr"),
    (0x0001_041f, "tr"),
    (0x0000_0022, "ur"),
    (0x0000_0422, "ur"),
    (0x0002_0422, "ur"),
    (0x0000_0023, "bl"),
    (0x0000_0423, "bl"),
    (0x0000_0025, "et"),
    (0x0000_0425, "et"),
    (0x0000_0026, "lv"),
    (0x0000_0426, "lv"),
    (0x0001_0426, "lv"),
    (0x0000_0027, "lt"),
    (0x0000_0427, "lt"),
    (0x0001_0427, "lt"),
    (0x0002_0427, "lt"),
    (0x0000_0028, "tj"),
    (0x0000_0428, "tj"),
    (0x0000_002a, "vi"),
    (0x0000_042a, "vi"),
    (0x0000_002b, "hy"),
    (0x0000_042b, "hy"),
    (0x0001_042b, "hy"),
    (0x0000_002c, "az"),
    (0x0000_042c, "az"),
    (0x0000_082c, "az"),
    (0x0000_002f, "mk"),
    (0x0000_042f, "mk"),
    (0x0001_042f, "mk"),
    (0x0000_0037, "ka"),
    (0x0000_0437, "ka"),
    (0x0001_0437, "ka"),
    (0x0002_0437, "ka"),
    (0x0000_0038, "fo"),
    (0x0000_0438, "fo"),
    (0x0000_003a, "mt"),
    (0x0000_043a, "mt"),
    (0x0001_043a, "mt"),
    (0x0000_003f, "kk"),
    (0x0000_043f, "kk"),
    (0x0000_0040, "ky"),
    (0x0000_0440, "ky"),
    (0x0000_0043, "uz"),
    (0x0000_0843, "uz"),
    (0x0000_0042, "tm"),
    (0x0000_0442, "tm"),
    (0x0000_0044, "tt"),
    (0x0000_0444, "tt"),
];

/// One pass of the `get_kb()` switch over [`KEYBOARD_TABLE`].
fn lookup_keyboard(key: u32) -> Option<&'static str> {
    KEYBOARD_TABLE
        .iter()
        .find_map(|(id, kb)| if *id == key { Some(*kb) } else { None })
}

/// The DOS keyboard code for a Windows keyboard id, porting `get_kb()`
/// (`dos_locale.c:440-758`) with its three passes exactly: (a) the full
/// `keyboard_id`, (b) its primary language (`keyboard_id & 0x3ff`, the
/// `PRIMARYLANGID` fallback of pass 1), (c) the primary language of the
/// system id (pass 2, after `PRIMARYLANGID(GetSystemDefaultLangID())`).
/// Anything unmatched reads as `"us"` (the final `return "us"`).
///
/// `keyboard_id` is the `GetKeyboardLayoutNameA` value parsed as hex;
/// `system_primary_language` is the `GetSystemDefaultLangID` value, of
/// which only the low 10 bits are used — callers may pass the full
/// language id, the mask is applied here. Upstream logs the raw KBID and
/// the pass transitions; those log lines stay with the caller — only the
/// decision is ported.
#[must_use]
pub fn keyboard_for(keyboard_id: u32, system_primary_language: u16) -> &'static str {
    if let Some(kb) = lookup_keyboard(keyboard_id) {
        return kb;
    }
    if let Some(kb) = lookup_keyboard(keyboard_id & 0x3ff) {
        return kb;
    }
    if let Some(kb) = lookup_keyboard(u32::from(system_primary_language) & 0x3ff) {
        return kb;
    }
    "us"
}

/// The EGA file holding `codepage`, porting `ms_get_ega`
/// (`dos_locale.c:790-820`) and `fd_get_ega` (`dos_locale.c:824-952`), or
/// `None` when no file holds it (upstream returns NULL and the caller
/// falls back to the driver default).
///
/// Fidelity quirk, kept on purpose: codepages 30003/30029/30030/58335 map
/// to `"ega12"` with no `.cpx` extension (`dos_locale.c:905-909`) — that
/// is what the reference passes to `mode con codepage prepare`, so the
/// byte-exact plan repeats it.
#[must_use]
pub fn ega_file(flavor: DosFlavor, codepage: u32) -> Option<&'static str> {
    match flavor {
        DosFlavor::MsDos => match codepage {
            437 | 850 | 852 | 860 | 863 | 865 => Some("ega.cpi"),
            857 | 861 | 869 | 737 => Some("ega2.cpi"),
            775 | 855 | 866 => Some("ega3.cpi"),
            _ => None,
        },
        DosFlavor::FreeDos => match codepage {
            437 | 850 | 852 | 853 | 857 | 858 => Some("ega.cpx"),
            775 | 859 | 1116 | 1117 | 1118 | 1119 => Some("ega2.cpx"),
            771 | 772 | 808 | 855 | 866 | 872 => Some("ega3.cpx"),
            848 | 849 | 1125 | 1131 | 3012 | 30010 => Some("ega4.cpx"),
            113 | 737 | 851 | 869 => Some("ega5.cpx"),
            899 | 30008 | 58210 | 59829 | 60258 | 60853 => Some("ega6.cpx"),
            30011 | 30013 | 30014 | 30017 | 30018 | 30019 => Some("ega7.cpx"),
            770 | 773 | 774 | 777 | 778 => Some("ega8.cpx"),
            860 | 861 | 863 | 865 | 867 => Some("ega9.cpx"),
            667 | 668 | 790 | 991 | 3845 => Some("ega10.cpx"),
            30000 | 30001 | 30004 | 30007 | 30009 => Some("ega11.cpx"),
            30003 | 30029 | 30030 | 58335 => Some("ega12"),
            895 | 30002 | 58152 | 59234 | 62306 => Some("ega13.cpx"),
            30006 | 30012 | 30015 | 30016 | 30020 | 30021 => Some("ega14.cpx"),
            // Upstream lists each label (`dos_locale.c:923-930`); the six
            // are consecutive, hence the range.
            30023..=30028 => Some("ega15.cpx"),
            3021 | 30005 | 30022 | 30031 | 30032 => Some("ega16.cpx"),
            862 | 864 | 30034 | 30033 | 30039 | 30040 => Some("ega17.cpx"),
            856 | 3846 | 3848 => Some("ega18.cpx"),
            _ => None,
        },
    }
}

/// The FreeDOS-only codepage transliteration (`fd_upgrade_cp`,
/// `dos_locale.c:956-963`): 850 becomes 858 (Latin-1 with Euro), anything
/// else passes through. MS-DOS maps nothing, so the MS-DOS flavor is the
/// identity. Upstream applies the upgrade only when an EGA file was found
/// (the `else if (bFreeDOS)`); [`plan`] preserves that — the EGA-fallback
/// path keeps the driver default verbatim.
#[must_use]
pub fn upgrade_codepage(flavor: DosFlavor, codepage: u32) -> u32 {
    match flavor {
        DosFlavor::FreeDos if codepage == 850 => 858,
        _ => codepage,
    }
}

/// The host-locale input to [`plan`]: the Windows-equivalent values the
/// reference reads via `GetKeyboardLayoutNameA` (parsed as hex),
/// `GetSystemDefaultLangID` and `GetOEMCP`. We never read the host locale
/// ourselves — the caller supplies all three, so plans are reproducible
/// and host-independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locale {
    /// The keyboard-layout name value (`GetKeyboardLayoutNameA`, hex).
    pub keyboard_id: u32,
    /// The system default language id (`GetSystemDefaultLangID`); only
    /// its primary language (low 10 bits) is used.
    pub system_language_id: u16,
    /// The OEM codepage (`GetOEMCP`); a caller seeing UTF-8 (65001) must
    /// resolve the real system codepage first.
    pub oem_codepage: u32,
}

impl Locale {
    /// US keyboard, US system language, codepage 437
    /// (`kbid = 0x00000409` default, `cp = 437`).
    #[must_use]
    pub fn us() -> Self {
        Self {
            keyboard_id: 0x0409,
            system_language_id: 0x0409,
            oem_codepage: 437,
        }
    }
}

/// The decided locale plus the byte-exact file contents: the pure result
/// of `SetDOSLocale` (`dos_locale.c:966-1072`) with the filesystem and
/// logging side effects removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalePlan {
    keyboard: &'static str,
    keyboard_name: Option<&'static str>,
    driver: KeyboardDriver,
    codepage: u32,
    codepage_name: Option<&'static str>,
    ega_file: &'static str,
    config_sys: Option<Vec<u8>>,
    autoexec_bat: Vec<u8>,
    messages: Vec<String>,
}

impl LocalePlan {
    /// The DOS keyboard code (`"us"` after the unsupported-keyboard
    /// fallback).
    #[must_use]
    pub fn keyboard(&self) -> &'static str {
        self.keyboard
    }

    /// The human-readable keyboard name, or `None` when the code has no
    /// table row (rendered as `<NULL>` in messages and files).
    #[must_use]
    pub fn keyboard_name(&self) -> Option<&'static str> {
        self.keyboard_name
    }

    /// The driver serving [`keyboard`](Self::keyboard).
    #[must_use]
    pub fn driver(&self) -> KeyboardDriver {
        self.driver
    }

    /// The final codepage: the OEM codepage, upgraded (FreeDOS 850 to
    /// 858) or replaced by the driver default on the EGA fallback.
    #[must_use]
    pub fn codepage(&self) -> u32 {
        self.codepage
    }

    /// The human-readable codepage name, or `None` when the codepage has
    /// no table row (rendered as `<NULL>` in messages and files).
    #[must_use]
    pub fn codepage_name(&self) -> Option<&'static str> {
        self.codepage_name
    }

    /// The EGA file for [`codepage`](Self::codepage): the mapped file, or
    /// the flavor default (`ega.cpi` / `ega.cpx`) on the EGA fallback.
    #[must_use]
    pub fn ega_file(&self) -> &'static str {
        self.ega_file
    }

    /// The `CONFIG.SYS` bytes, or `None` in the 437/US special case where
    /// upstream writes only `AUTOEXEC.BAT`. `None` marks "no file" as
    /// distinct from an empty file — the caller must not create it.
    #[must_use]
    pub fn config_sys(&self) -> Option<&[u8]> {
        self.config_sys.as_deref()
    }

    /// The `AUTOEXEC.BAT` bytes, always present.
    #[must_use]
    pub fn autoexec_bat(&self) -> &[u8] {
        &self.autoexec_bat
    }

    /// The reference log lines in reference order (ASCII only): the
    /// unsupported-keyboard fallback when it fires, the keyboard choice,
    /// the EGA fallback when it fires, then the codepage choice. The two
    /// upstream `Successfully wrote ...` lines are intentionally absent —
    /// this module writes nothing, so it claims no write.
    #[must_use]
    pub fn messages(&self) -> &[String] {
        &self.messages
    }
}

/// A missing human-readable name as upstream prints it when handed NULL:
/// `<NULL>`. Used in messages and file bytes wherever `kb_to_hr` /
/// `cp_to_hr` could return NULL.
fn display_or_null(name: Option<&'static str>) -> &'static str {
    name.unwrap_or("<NULL>")
}

/// The `CONFIG.SYS` bytes for the general case (`dos_locale.c:1025-1048`),
/// byte-exact: the FreeDOS `!MENUCOLOR` header with the 31-byte `0xCD`
/// rule, `MENUDEFAULT=1,5`, the two menu items, and the flavor-specific
/// tail (`MENU` / `12?` vs `[1]` / `device=` / `[2]`).
fn config_sys_bytes(
    flavor: DosFlavor,
    keyboard_hr: &str,
    codepage_hr: &str,
    codepage: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    let us_keyboard = display_or_null(keyboard_name("us"));
    let us_codepage = display_or_null(codepage_name(437));
    if flavor == DosFlavor::FreeDos {
        out.extend_from_slice(
            b"!MENUCOLOR=7,0\nMENU\nMENU   FreeDOS Language Selection Menu\nMENU   ",
        );
        out.extend_from_slice(&[0xCDu8; 31]);
        out.extend_from_slice(b"\nMENU\nMENUDEFAULT=1,5\n");
        let first = format!(
            "MENU 1) Use {keyboard_hr} keyboard with {codepage_hr} codepage [{codepage}]\n"
        );
        out.extend_from_slice(first.as_bytes());
        let second =
            format!("MENU 2) Use {us_keyboard} keyboard with {us_codepage} codepage [437]\n");
        out.extend_from_slice(second.as_bytes());
        out.extend_from_slice(b"MENU\n12?\n");
    } else {
        out.extend_from_slice(b"[MENU]\nMENUDEFAULT=1,5\n");
        let first = format!(
            "MENUITEM=1, Use {keyboard_hr} keyboard with {codepage_hr} codepage [{codepage}]\n"
        );
        out.extend_from_slice(first.as_bytes());
        let second =
            format!("MENUITEM=2, Use {us_keyboard} keyboard with {us_codepage} codepage [437]\n");
        out.extend_from_slice(second.as_bytes());
        out.extend_from_slice(b"[1]\ndevice=\\locale\\display.sys con=(ega,,1)\n[2]\n");
    }
    out
}

/// The `AUTOEXEC.BAT` bytes for the general case
/// (`dos_locale.c:1050-1069`), byte-exact: path setup, the FreeDOS-only
/// `display` line, `GOTO %CONFIG%`, the `:1` codepage/keyboard stanza and
/// the `:2` tail.
fn autoexec_bytes(
    flavor: DosFlavor,
    keyboard: &str,
    driver: KeyboardDriver,
    ega: &str,
    codepage: u32,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"@echo off\n");
    out.extend_from_slice(b"set PATH=.;\\;\\LOCALE\n");
    if flavor == DosFlavor::FreeDos {
        out.extend_from_slice(b"display con=(ega,,1)\n");
    }
    out.extend_from_slice(b"GOTO %CONFIG%\n");
    out.extend_from_slice(b":1\n");
    let prepare = format!("mode con codepage prepare=(({codepage}) \\locale\\{ega}) > NUL\n");
    out.extend_from_slice(prepare.as_bytes());
    let select = format!("mode con codepage select={codepage} > NUL\n");
    out.extend_from_slice(select.as_bytes());
    let keyb = format!("keyb {keyboard},,\\locale\\{}\n", driver.name());
    out.extend_from_slice(keyb.as_bytes());
    out.extend_from_slice(b":2\n");
    out
}

/// The `AUTOEXEC.BAT` bytes for the 437/US special case
/// (`dos_locale.c:1008-1023`): a notification only, no codepage or
/// keyboard setup.
fn autoexec_us_only_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"@echo off\n");
    out.extend_from_slice(b"set PATH=.;\\;\\LOCALE\n");
    let line = format!(
        "echo Using {} keyboard with {} codepage [437]\n",
        display_or_null(keyboard_name("us")),
        display_or_null(codepage_name(437))
    );
    out.extend_from_slice(line.as_bytes());
    out
}

/// Decide the DOS locale and render the file bytes, porting `SetDOSLocale`
/// (`dos_locale.c:966-1072`) as a pure function: keyboard selection with
/// the unsupported-keyboard fallback to `"us"`, driver selection, the EGA
/// fallback (codepage becomes the driver default, EGA file the flavor
/// default), the FreeDOS 850-to-858 upgrade, and the 437/US special case
/// where only `AUTOEXEC.BAT` is produced.
///
/// No filesystem, no `Fat32`, no flush, no logging side effects — the
/// [`messages`](LocalePlan::messages) list carries the reference log
/// lines instead.
#[must_use]
pub fn plan(flavor: DosFlavor, locale: &Locale) -> LocalePlan {
    let mut messages = Vec::new();
    let mut keyboard = keyboard_for(locale.keyboard_id, locale.system_language_id);
    let mut driver = driver_for(flavor, keyboard);
    if driver.is_none() {
        messages.push(format!(
            "Keyboard id '{keyboard}' is not supported - falling back to 'us'"
        ));
        keyboard = "us";
        // "us" sits in the first list of both flavors, so this always
        // succeeds; the fallback keeps the function total without a panic.
        driver = driver_for(flavor, keyboard);
    }
    let driver = driver.unwrap_or(KeyboardDriver::KeyboardSys);
    let kb_name = keyboard_name(keyboard);
    messages.push(format!(
        "Will use DOS keyboard '{keyboard}' [{}]",
        display_or_null(kb_name)
    ));

    let mut codepage = locale.oem_codepage;
    let ega: &'static str = match ega_file(flavor, codepage) {
        Some(file) => {
            if flavor == DosFlavor::FreeDos {
                codepage = upgrade_codepage(flavor, codepage);
            }
            file
        }
        None => {
            messages.push(format!(
                "Unable to find an EGA file with codepage {codepage} [{}]",
                display_or_null(codepage_name(codepage))
            ));
            codepage = driver.default_codepage();
            match flavor {
                DosFlavor::MsDos => "ega.cpi",
                DosFlavor::FreeDos => "ega.cpx",
            }
        }
    };
    let cp_name = codepage_name(codepage);
    messages.push(format!(
        "Will use codepage {codepage} [{}]",
        display_or_null(cp_name)
    ));

    if codepage == 437 && keyboard == "us" {
        return LocalePlan {
            keyboard,
            keyboard_name: kb_name,
            driver,
            codepage,
            codepage_name: cp_name,
            ega_file: ega,
            config_sys: None,
            autoexec_bat: autoexec_us_only_bytes(),
            messages,
        };
    }
    let config = config_sys_bytes(
        flavor,
        display_or_null(kb_name),
        display_or_null(cp_name),
        codepage,
    );
    let autoexec = autoexec_bytes(flavor, keyboard, driver, ega, codepage);
    LocalePlan {
        keyboard,
        keyboard_name: kb_name,
        driver,
        codepage,
        codepage_name: cp_name,
        ega_file: ega,
        config_sys: Some(config),
        autoexec_bat: autoexec,
        messages,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_hold_56_keyboards_and_115_codepages() {
        assert_eq!(KB_HR_LIST.len(), 56, "every kb_hr_list row is ported");
        assert_eq!(CP_HR_LIST.len(), 115, "every cp_hr_list row is ported");
        // Verbatim samples, pinned exactly as the C file spells them.
        assert_eq!(
            keyboard_name("us"),
            Some("US-English"),
            "us spells US-English, not US"
        );
        assert_eq!(
            keyboard_name("gr"),
            Some("German"),
            "German lives under gr, not de"
        );
        assert_eq!(
            keyboard_name("sg"),
            Some("Swiss-German"),
            "a hyphenated sample survives"
        );
        assert_eq!(
            keyboard_name("de"),
            None,
            "no de row exists upstream, so none is ported"
        );
        assert_eq!(
            keyboard_name("ko"),
            None,
            "ko stays commented out upstream and stays absent here"
        );
        assert_eq!(
            keyboard_name("xx"),
            None,
            "an unknown code misses instead of asserting"
        );
        assert_eq!(
            codepage_name(437),
            Some("US-English"),
            "437 spells US-English, not United States"
        );
        assert_eq!(
            codepage_name(850),
            Some("Western-European"),
            "850 keeps its hyphen"
        );
        assert_eq!(
            codepage_name(858),
            Some("Western-European (Euro)"),
            "the upgrade target has a row"
        );
        assert_eq!(
            codepage_name(113),
            Some("Lat-Yugoslavian"),
            "the first table row survives"
        );
        assert_eq!(
            codepage_name(65001),
            Some("Unicode (UTF-8)"),
            "the last table row survives"
        );
        assert_eq!(
            codepage_name(999_999),
            None,
            "an unknown codepage misses instead of asserting"
        );
    }

    #[test]
    fn keyboard_table_holds_every_switch_label() {
        assert_eq!(
            KEYBOARD_TABLE.len(),
            157,
            "every get_kb() case label is ported"
        );
        // Spot checks across the three groups of labels.
        for (id, want) in [
            (0x0001_0401u32, "ar"),
            (0x0000_0807u32, "sg"),
            (0x0000_0452u32, "uk"),
            (0x0001_083bu32, "su"),
            (0x0000_046eu32, "fr"),
            (0x0000_201au32, "yc"),
            (0x0002_0422u32, "ur"),
            (0x0001_0437u32, "ka"),
            (0x0000_0444u32, "tt"),
        ] {
            assert_eq!(
                lookup_keyboard(id),
                Some(want),
                "label {id:#010x} maps to {want}"
            );
        }
        assert_eq!(
            lookup_keyboard(0x0000_041e),
            None,
            "Thai stays in the #if 0 block upstream and stays absent here"
        );
    }

    #[test]
    fn keyboard_for_matches_exact_ids() {
        assert_eq!(keyboard_for(0x0409, 0x0409), "us", "plain US");
        assert_eq!(keyboard_for(0x0407, 0x0409), "gr", "plain German");
        assert_eq!(keyboard_for(0x0419, 0x0409), "ru", "plain Russian");
        assert_eq!(
            keyboard_for(0x0001_0407, 0x0409),
            "gr",
            "a full variant id matches exactly"
        );
        assert_eq!(
            keyboard_for(0x0000_0807, 0x0409),
            "sg",
            "Swiss German is its own code, not gr"
        );
    }

    #[test]
    fn keyboard_for_falls_back_to_the_primary_language() {
        // 0x00020407 is no table label, but its PRIMARYLANGID (0x007) is
        // German; the system language is US, so "gr" proves pass 2 ran —
        // pass 3 would have answered "us".
        assert_eq!(
            keyboard_for(0x0002_0407, 0x0409),
            "gr",
            "an unknown variant falls back to its primary language"
        );
    }

    #[test]
    fn keyboard_for_falls_back_to_the_system_language() {
        // 0x9999 matches nothing, and neither does its primary language
        // (0x199); the German system id answers instead — pass 3.
        assert_eq!(
            keyboard_for(0x9999, 0x0407),
            "gr",
            "an unknown id falls back to the system language"
        );
    }

    #[test]
    fn keyboard_for_defaults_to_us() {
        // Thai (0x041e) is absent from the table and its primary language
        // (0x001e) is absent too, so even a Thai system id defaults.
        assert_eq!(
            keyboard_for(0x041e, 0x041e),
            "us",
            "nothing matching defaults to us"
        );
        assert_eq!(
            keyboard_for(0x9999, 0x041e),
            "us",
            "an unknown id with an unusable system id defaults to us"
        );
    }

    #[test]
    fn driver_for_picks_each_ms_driver() {
        assert_eq!(
            driver_for(DosFlavor::MsDos, "gr"),
            Some(KeyboardDriver::KeyboardSys),
            "gr rides keyboard.sys"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "bg"),
            Some(KeyboardDriver::Keybrd2),
            "bg rides keybrd2.sys"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "ru"),
            Some(KeyboardDriver::Keybrd2),
            "ru sits in keybrd2.sys first, so it wins there"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "bl"),
            Some(KeyboardDriver::Keybrd3),
            "bl rides keybrd3.sys"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "he"),
            Some(KeyboardDriver::Keybrd4),
            "he rides keybrd4.sys"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "us"),
            Some(KeyboardDriver::KeyboardSys),
            "us is in the first list, so it wins there"
        );
    }

    #[test]
    fn driver_for_picks_each_freedos_driver() {
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "co"),
            Some(KeyboardDriver::KeyboardSys),
            "co rides keyboard.sys"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "bg"),
            Some(KeyboardDriver::Keybrd2),
            "bg rides keybrd2.sys"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "az"),
            Some(KeyboardDriver::Keybrd3),
            "az rides keybrd3.sys"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "ar"),
            Some(KeyboardDriver::Keybrd4),
            "ar rides keybrd4.sys"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "us"),
            Some(KeyboardDriver::KeyboardSys),
            "us is in the first list on both flavors"
        );
    }

    #[test]
    fn driver_for_splits_the_flavor_only_codes() {
        // Codes living in only one flavor's lists decide per flavor.
        assert_eq!(
            driver_for(DosFlavor::MsDos, "sl"),
            Some(KeyboardDriver::KeyboardSys),
            "sl is MS-only"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "sl"),
            None,
            "sl has no FreeDOS driver"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "co"),
            Some(KeyboardDriver::KeyboardSys),
            "co is FreeDOS-only"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "co"),
            None,
            "co has no MS-DOS driver"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "he"),
            Some(KeyboardDriver::Keybrd4),
            "he is MS-only"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "he"),
            None,
            "he has no FreeDOS driver"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "az"),
            Some(KeyboardDriver::Keybrd3),
            "az is FreeDOS-only"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "az"),
            None,
            "az has no MS-DOS driver"
        );
    }

    #[test]
    fn driver_for_matches_exact_ascii_only() {
        assert_eq!(
            driver_for(DosFlavor::MsDos, "US"),
            None,
            "no case folding: upper-case US misses"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "Gr"),
            None,
            "no case folding: mixed-case Gr misses"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "xx"),
            None,
            "an unknown code misses on both flavors"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "xx"),
            None,
            "an unknown code misses on both flavors"
        );
    }

    #[test]
    fn driver_lists_match_the_reference_counts_and_probes() {
        // Lengths parsed from dos_locale.c:133-164 (ms_kb1..4, fd_kb1..4):
        // a dropped code changes resolution — an unlisted layout falls
        // back to "us" and can collapse the plan into the 437/US special
        // case — so every list pins its count.
        assert_eq!(MS_KB1.len(), 23, "ms_kb1 holds 23 codes");
        assert_eq!(MS_KB2.len(), 21, "ms_kb2 holds 21 codes");
        assert_eq!(MS_KB3.len(), 21, "ms_kb3 holds 21 codes");
        assert_eq!(MS_KB4.len(), 6, "ms_kb4 holds 6 codes");
        assert_eq!(FD_KB1.len(), 28, "fd_kb1 holds 28 codes");
        assert_eq!(FD_KB2.len(), 10, "fd_kb2 holds 10 codes");
        assert_eq!(FD_KB3.len(), 21, "fd_kb3 holds 21 codes");
        assert_eq!(FD_KB4.len(), 11, "fd_kb4 holds 11 codes");
        // One probe per list, each satisfiable only by that list under
        // first-list-wins, so a move or rename breaks its probe. Lengths
        // alone would miss a rename (the count stays), hence "po": a
        // rename to "pp" still counts 23 but resolves to None.
        assert_eq!(
            driver_for(DosFlavor::MsDos, "po"),
            Some(KeyboardDriver::KeyboardSys),
            "po is MS keyboard.sys-only"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "bg"),
            Some(KeyboardDriver::Keybrd2),
            "bg is MS keybrd2.sys-only"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "ur"),
            Some(KeyboardDriver::Keybrd3),
            "ur is MS keybrd3.sys-only"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "ar"),
            Some(KeyboardDriver::Keybrd4),
            "ar is MS keybrd4.sys-only"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "yu"),
            Some(KeyboardDriver::KeyboardSys),
            "yu is FreeDOS keyboard.sys-only"
        );
        assert_eq!(
            driver_for(DosFlavor::MsDos, "yu"),
            Some(KeyboardDriver::KeyboardSys),
            "yu is MS keyboard.sys-only too"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "ce"),
            Some(KeyboardDriver::Keybrd2),
            "ce is FreeDOS keybrd2.sys-only"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "et"),
            Some(KeyboardDriver::Keybrd3),
            "et is FreeDOS keybrd3.sys-only"
        );
        assert_eq!(
            driver_for(DosFlavor::FreeDos, "bn"),
            Some(KeyboardDriver::Keybrd4),
            "bn is FreeDOS keybrd4.sys-only"
        );
    }

    #[test]
    fn driver_names_and_defaults_match_kbdrv_data() {
        assert_eq!(
            KeyboardDriver::KeyboardSys.name(),
            "keyboard.sys",
            "first driver name"
        );
        assert_eq!(
            KeyboardDriver::Keybrd2.name(),
            "keybrd2.sys",
            "second driver name"
        );
        assert_eq!(
            KeyboardDriver::Keybrd3.name(),
            "keybrd3.sys",
            "third driver name"
        );
        assert_eq!(
            KeyboardDriver::Keybrd4.name(),
            "keybrd4.sys",
            "fourth driver name"
        );
        assert_eq!(
            KeyboardDriver::KeyboardSys.default_codepage(),
            437,
            "first driver default"
        );
        assert_eq!(
            KeyboardDriver::Keybrd2.default_codepage(),
            850,
            "second driver default"
        );
        assert_eq!(
            KeyboardDriver::Keybrd3.default_codepage(),
            850,
            "third driver default"
        );
        assert_eq!(
            KeyboardDriver::Keybrd4.default_codepage(),
            853,
            "fourth driver default"
        );
    }

    #[test]
    fn ega_file_matches_both_flavors() {
        assert_eq!(
            ega_file(DosFlavor::MsDos, 437),
            Some("ega.cpi"),
            "MS-DOS United States"
        );
        assert_eq!(
            ega_file(DosFlavor::MsDos, 850),
            Some("ega.cpi"),
            "MS-DOS Latin-1 shares ega.cpi"
        );
        assert_eq!(
            ega_file(DosFlavor::MsDos, 737),
            Some("ega2.cpi"),
            "MS-DOS Greek II"
        );
        assert_eq!(
            ega_file(DosFlavor::MsDos, 869),
            Some("ega2.cpi"),
            "MS-DOS Greek"
        );
        assert_eq!(
            ega_file(DosFlavor::MsDos, 775),
            Some("ega3.cpi"),
            "MS-DOS Baltic"
        );
        assert_eq!(
            ega_file(DosFlavor::MsDos, 866),
            Some("ega3.cpi"),
            "MS-DOS Cyrillic II"
        );
        assert_eq!(
            ega_file(DosFlavor::MsDos, 1252),
            None,
            "MS-DOS has no EGA for 1252"
        );
        assert_eq!(
            ega_file(DosFlavor::FreeDos, 437),
            Some("ega.cpx"),
            "FreeDOS United States"
        );
        assert_eq!(
            ega_file(DosFlavor::FreeDos, 858),
            Some("ega.cpx"),
            "FreeDOS Latin-1 with Euro"
        );
        assert_eq!(
            ega_file(DosFlavor::FreeDos, 850),
            Some("ega.cpx"),
            "FreeDOS Latin-1 before the upgrade"
        );
        assert_eq!(
            ega_file(DosFlavor::FreeDos, 866),
            Some("ega3.cpx"),
            "FreeDOS Cyrillic Russian"
        );
        assert_eq!(
            ega_file(DosFlavor::FreeDos, 1252),
            None,
            "FreeDOS has no EGA for 1252 either"
        );
        // The same codepage resolves to different files per flavor.
        assert_ne!(
            ega_file(DosFlavor::MsDos, 850),
            ega_file(DosFlavor::FreeDos, 850),
            "850 is ega.cpi on MS-DOS but ega.cpx on FreeDOS"
        );
    }

    #[test]
    fn ega_file_keeps_the_ega12_quirk() {
        // Upstream maps these to "ega12" with no .cpx extension; the plan
        // repeats the quirk byte for byte.
        for cp in [30003u32, 30029, 30030, 58335] {
            assert_eq!(
                ega_file(DosFlavor::FreeDos, cp),
                Some("ega12"),
                "codepage {cp} maps to the extensionless ega12"
            );
        }
        let file = ega_file(DosFlavor::FreeDos, 30003).expect("ega12 maps");
        assert!(!file.contains('.'), "ega12 carries no extension: {file}");
    }

    #[test]
    fn upgrade_codepage_maps_850_to_858_on_freedos_only() {
        assert_eq!(
            upgrade_codepage(DosFlavor::FreeDos, 850),
            858,
            "FreeDOS upgrades Latin-1 to Latin-1 with Euro"
        );
        assert_eq!(
            upgrade_codepage(DosFlavor::FreeDos, 858),
            858,
            "the upgrade is idempotent"
        );
        assert_eq!(
            upgrade_codepage(DosFlavor::FreeDos, 437),
            437,
            "other codepages pass through"
        );
        assert_eq!(
            upgrade_codepage(DosFlavor::MsDos, 850),
            850,
            "MS-DOS maps nothing"
        );
        assert_eq!(
            upgrade_codepage(DosFlavor::MsDos, 437),
            437,
            "MS-DOS leaves 437 alone"
        );
    }

    /// The exact MS-DOS `CONFIG.SYS` for German / Nordic (865).
    fn ms_german_config() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"[MENU]\n");
        out.extend_from_slice(b"MENUDEFAULT=1,5\n");
        out.extend_from_slice(b"MENUITEM=1, Use German keyboard with Nordic codepage [865]\n");
        out.extend_from_slice(
            b"MENUITEM=2, Use US-English keyboard with US-English codepage [437]\n",
        );
        out.extend_from_slice(b"[1]\n");
        out.extend_from_slice(b"device=\\locale\\display.sys con=(ega,,1)\n");
        out.extend_from_slice(b"[2]\n");
        out
    }

    /// The exact MS-DOS `AUTOEXEC.BAT` for German / Nordic (865).
    fn ms_german_autoexec() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"@echo off\n");
        out.extend_from_slice(b"set PATH=.;\\;\\LOCALE\n");
        out.extend_from_slice(b"GOTO %CONFIG%\n");
        out.extend_from_slice(b":1\n");
        out.extend_from_slice(b"mode con codepage prepare=((865) \\locale\\ega.cpi) > NUL\n");
        out.extend_from_slice(b"mode con codepage select=865 > NUL\n");
        out.extend_from_slice(b"keyb gr,,\\locale\\keyboard.sys\n");
        out.extend_from_slice(b":2\n");
        out
    }

    #[test]
    fn ms_dos_german_plan_is_byte_exact() {
        let locale = Locale {
            keyboard_id: 0x0407,
            system_language_id: 0x0409,
            oem_codepage: 865,
        };
        let done = plan(DosFlavor::MsDos, &locale);
        assert_eq!(done.keyboard(), "gr", "German survives");
        assert_eq!(
            done.keyboard_name(),
            Some("German"),
            "the human-readable keyboard name"
        );
        assert_eq!(
            done.driver(),
            KeyboardDriver::KeyboardSys,
            "gr rides keyboard.sys"
        );
        assert_eq!(done.codepage(), 865, "MS-DOS upgrades nothing");
        assert_eq!(
            done.codepage_name(),
            Some("Nordic"),
            "the human-readable codepage name"
        );
        assert_eq!(done.ega_file(), "ega.cpi", "Nordic ships in ega.cpi");
        assert_eq!(
            done.config_sys(),
            Some(ms_german_config().as_slice()),
            "CONFIG.SYS is byte-exact"
        );
        assert_eq!(
            done.autoexec_bat(),
            ms_german_autoexec().as_slice(),
            "AUTOEXEC.BAT is byte-exact"
        );
        let messages: Vec<&str> = done.messages().iter().map(String::as_str).collect();
        assert_eq!(
            messages,
            [
                "Will use DOS keyboard 'gr' [German]",
                "Will use codepage 865 [Nordic]",
            ],
            "the two always-on lines in reference order"
        );
    }

    /// The exact FreeDOS `CONFIG.SYS` for Dutch / 850-upgraded-to-858.
    fn fd_dutch_config() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"!MENUCOLOR=7,0\n");
        out.extend_from_slice(b"MENU\n");
        out.extend_from_slice(b"MENU   FreeDOS Language Selection Menu\n");
        out.extend_from_slice(b"MENU   ");
        out.extend_from_slice(&[0xCDu8; 31]);
        out.extend_from_slice(b"\n");
        out.extend_from_slice(b"MENU\n");
        out.extend_from_slice(b"MENUDEFAULT=1,5\n");
        out.extend_from_slice(
            b"MENU 1) Use Dutch keyboard with Western-European (Euro) codepage [858]\n",
        );
        out.extend_from_slice(b"MENU 2) Use US-English keyboard with US-English codepage [437]\n");
        out.extend_from_slice(b"MENU\n");
        out.extend_from_slice(b"12?\n");
        out
    }

    /// The exact FreeDOS `AUTOEXEC.BAT` for Dutch / 858.
    fn fd_dutch_autoexec() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"@echo off\n");
        out.extend_from_slice(b"set PATH=.;\\;\\LOCALE\n");
        out.extend_from_slice(b"display con=(ega,,1)\n");
        out.extend_from_slice(b"GOTO %CONFIG%\n");
        out.extend_from_slice(b":1\n");
        out.extend_from_slice(b"mode con codepage prepare=((858) \\locale\\ega.cpx) > NUL\n");
        out.extend_from_slice(b"mode con codepage select=858 > NUL\n");
        out.extend_from_slice(b"keyb nl,,\\locale\\keyboard.sys\n");
        out.extend_from_slice(b":2\n");
        out
    }

    #[test]
    fn freedos_dutch_plan_is_byte_exact() {
        let locale = Locale {
            keyboard_id: 0x0413,
            system_language_id: 0x0409,
            oem_codepage: 850,
        };
        let done = plan(DosFlavor::FreeDos, &locale);
        assert_eq!(done.keyboard(), "nl", "Dutch survives");
        assert_eq!(
            done.keyboard_name(),
            Some("Dutch"),
            "the human-readable keyboard name"
        );
        assert_eq!(
            done.driver(),
            KeyboardDriver::KeyboardSys,
            "nl rides keyboard.sys"
        );
        assert_eq!(
            done.codepage(),
            858,
            "FreeDOS upgrades 850 to 858 once an EGA file matched"
        );
        assert_eq!(
            done.codepage_name(),
            Some("Western-European (Euro)"),
            "the upgraded codepage has its own row"
        );
        assert_eq!(done.ega_file(), "ega.cpx", "the matched EGA file");
        assert_eq!(
            done.config_sys(),
            Some(fd_dutch_config().as_slice()),
            "CONFIG.SYS is byte-exact, rule line included"
        );
        assert_eq!(
            done.autoexec_bat(),
            fd_dutch_autoexec().as_slice(),
            "AUTOEXEC.BAT is byte-exact, display line included"
        );
        let messages: Vec<&str> = done.messages().iter().map(String::as_str).collect();
        assert_eq!(
            messages,
            [
                "Will use DOS keyboard 'nl' [Dutch]",
                "Will use codepage 858 [Western-European (Euro)]",
            ],
            "the two always-on lines in reference order"
        );
    }

    /// The exact 437/US `AUTOEXEC.BAT`: a notification only.
    fn us_only_autoexec() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"@echo off\n");
        out.extend_from_slice(b"set PATH=.;\\;\\LOCALE\n");
        out.extend_from_slice(b"echo Using US-English keyboard with US-English codepage [437]\n");
        out
    }

    #[test]
    fn us_437_writes_only_autoexec() {
        for flavor in [DosFlavor::MsDos, DosFlavor::FreeDos] {
            let done = plan(flavor, &Locale::us());
            assert_eq!(done.keyboard(), "us", "US survives on {flavor:?}");
            assert_eq!(
                done.driver(),
                KeyboardDriver::KeyboardSys,
                "us rides keyboard.sys on {flavor:?}"
            );
            assert_eq!(done.codepage(), 437, "437 stays on {flavor:?}");
            assert_eq!(
                done.config_sys(),
                None,
                "no CONFIG.SYS on {flavor:?}: upstream writes only AUTOEXEC.BAT"
            );
            assert_eq!(
                done.autoexec_bat(),
                us_only_autoexec().as_slice(),
                "AUTOEXEC.BAT is byte-exact on {flavor:?}"
            );
            let messages: Vec<&str> = done.messages().iter().map(String::as_str).collect();
            assert_eq!(
                messages,
                [
                    "Will use DOS keyboard 'us' [US-English]",
                    "Will use codepage 437 [US-English]",
                ],
                "the two always-on lines on {flavor:?}"
            );
        }
        assert_eq!(
            plan(DosFlavor::MsDos, &Locale::us()).ega_file(),
            "ega.cpi",
            "the MS-DOS EGA default still resolves"
        );
        assert_eq!(
            plan(DosFlavor::FreeDos, &Locale::us()).ega_file(),
            "ega.cpx",
            "the FreeDOS EGA default still resolves"
        );
    }

    #[test]
    fn unsupported_keyboard_falls_back_to_us() {
        // Chinese (0x0404) is a real get_kb() answer with no driver on
        // either flavor, so SetDOSLocale falls back to "us".
        let locale = Locale {
            keyboard_id: 0x0404,
            system_language_id: 0x0409,
            oem_codepage: 437,
        };
        for flavor in [DosFlavor::MsDos, DosFlavor::FreeDos] {
            let done = plan(flavor, &locale);
            assert_eq!(
                done.keyboard(),
                "us",
                "an unsupported code falls back on {flavor:?}"
            );
            assert_eq!(
                done.driver(),
                KeyboardDriver::KeyboardSys,
                "the fallback always lands on keyboard.sys"
            );
            assert_eq!(
                done.config_sys(),
                None,
                "the fallback lands in the 437/US special case"
            );
            assert_eq!(
                done.autoexec_bat(),
                us_only_autoexec().as_slice(),
                "the special-case AUTOEXEC.BAT on {flavor:?}"
            );
            let messages: Vec<&str> = done.messages().iter().map(String::as_str).collect();
            assert_eq!(
                messages,
                [
                    "Keyboard id 'ch' is not supported - falling back to 'us'",
                    "Will use DOS keyboard 'us' [US-English]",
                    "Will use codepage 437 [US-English]",
                ],
                "the fallback line leads, then the two always-on lines"
            );
            for line in done.messages() {
                assert!(line.is_ascii(), "stays ASCII: {line}");
            }
        }
    }

    #[test]
    fn missing_ega_falls_back_to_the_driver_default() {
        // 1252 has a human-readable row but no EGA file on either flavor.
        let german = Locale {
            keyboard_id: 0x0407,
            system_language_id: 0x0409,
            oem_codepage: 1252,
        };
        let done = plan(DosFlavor::MsDos, &german);
        assert_eq!(
            done.codepage(),
            437,
            "the MS-DOS fallback takes the keyboard.sys default"
        );
        assert_eq!(
            done.ega_file(),
            "ega.cpi",
            "the MS-DOS fallback takes the flavor default file"
        );
        let messages: Vec<&str> = done.messages().iter().map(String::as_str).collect();
        assert_eq!(
            messages,
            [
                "Will use DOS keyboard 'gr' [German]",
                "Unable to find an EGA file with codepage 1252 [Western European]",
                "Will use codepage 437 [US-English]",
            ],
            "the EGA line sits between the two always-on lines"
        );
        // German keyboard with the fallen-back 437 codepage: a full
        // CONFIG.SYS, not the 437/US special case.
        let config = done.config_sys().expect("a full CONFIG.SYS is planned");
        let text = core::str::from_utf8(config).expect("CONFIG.SYS stays ASCII");
        assert!(
            text.contains("MENUITEM=1, Use German keyboard with US-English codepage [437]"),
            "the fallen-back codepage reaches the menu: {text}"
        );
        let autoexec = core::str::from_utf8(done.autoexec_bat()).expect("AUTOEXEC.BAT stays ASCII");
        assert!(
            autoexec.contains("mode con codepage prepare=((437) \\locale\\ega.cpi) > NUL"),
            "the fallen-back EGA file reaches AUTOEXEC.BAT: {autoexec}"
        );
    }

    #[test]
    fn ega_fallback_skips_the_freedos_upgrade() {
        // Bulgarian rides keybrd2.sys (default 850); with no EGA file for
        // 1252 the fallback takes 850 verbatim — upstream's upgrade sits
        // in the `else if`, so it must not fire here.
        let bulgarian = Locale {
            keyboard_id: 0x0402,
            system_language_id: 0x0409,
            oem_codepage: 1252,
        };
        let done = plan(DosFlavor::FreeDos, &bulgarian);
        assert_eq!(done.keyboard(), "bg", "Bulgarian survives");
        assert_eq!(
            done.driver(),
            KeyboardDriver::Keybrd2,
            "bg rides keybrd2.sys"
        );
        assert_eq!(
            done.codepage(),
            850,
            "the fallback keeps 850 without upgrading to 858"
        );
        assert_eq!(
            done.codepage_name(),
            Some("Western-European"),
            "850 keeps its own row, not the Euro one"
        );
        assert_eq!(done.ega_file(), "ega.cpx", "the flavor default file");
        let messages: Vec<&str> = done.messages().iter().map(String::as_str).collect();
        assert_eq!(
            messages,
            [
                "Will use DOS keyboard 'bg' [Bulgarian]",
                "Unable to find an EGA file with codepage 1252 [Western European]",
                "Will use codepage 850 [Western-European]",
            ],
            "the EGA line sits between the two always-on lines"
        );
        let autoexec = core::str::from_utf8(done.autoexec_bat()).expect("AUTOEXEC.BAT stays ASCII");
        assert!(
            autoexec.contains("mode con codepage prepare=((850) \\locale\\ega.cpx) > NUL"),
            "the un-upgraded codepage reaches AUTOEXEC.BAT: {autoexec}"
        );
        assert!(
            autoexec.contains("keyb bg,,\\locale\\keybrd2.sys"),
            "the driver name reaches AUTOEXEC.BAT: {autoexec}"
        );
    }

    #[test]
    fn unknown_codepage_renders_null_without_panicking() {
        // 999999 has neither an EGA file nor a table row: the fallback
        // still resolves and the message renders <NULL> as upstream does.
        let locale = Locale {
            keyboard_id: 0x0409,
            system_language_id: 0x0409,
            oem_codepage: 999_999,
        };
        let done = plan(DosFlavor::MsDos, &locale);
        assert_eq!(
            done.codepage(),
            437,
            "the fallback still takes the driver default"
        );
        assert_eq!(
            done.codepage_name(),
            Some("US-English"),
            "the resolved codepage has a row"
        );
        let messages: Vec<&str> = done.messages().iter().map(String::as_str).collect();
        assert_eq!(
            messages,
            [
                "Will use DOS keyboard 'us' [US-English]",
                "Unable to find an EGA file with codepage 999999 [<NULL>]",
                "Will use codepage 437 [US-English]",
            ],
            "a missing name renders as <NULL>"
        );
    }

    #[test]
    fn locale_us_pins_the_reference_defaults() {
        let locale = Locale::us();
        assert_eq!(locale.keyboard_id, 0x0409, "the US layout id");
        assert_eq!(locale.system_language_id, 0x0409, "the US system id");
        assert_eq!(locale.oem_codepage, 437, "the US codepage");
    }
}
