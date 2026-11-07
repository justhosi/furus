//! Windows To Go tweaks on top of the generic `regf` editor (S21, slice 7 of 12).
//!
//! Question: after the image is applied, a Windows To Go USB must leave the
//! host's internal disks alone and must not offer automatic recovery, without
//! running the applied image's own Windows tools.
//!
//! What real Rufus does: it sets `SanPolicy` to `4` (offline internal disks)
//! under the current control set's `Services\partmgr\Parameters` in the
//! applied image's `Windows/System32/config/SYSTEM` hive, and it runs
//! `bcdedit /set {default} recoveryenabled no` (element `0x16000009` to
//! false) on both BCD stores. On Linux that needs no Wine and no Windows
//! tools: this module patches both hives host-side with the small in-crate
//! `regf` editor from [`super::regf`].
//!
//! Decision: [`offline_san_policy`] reads `Select\Current` to learn the
//! current control set number (`ControlSet001`, `ControlSet002`, ...; the
//! value is a DWORD), then sets
//! `ControlSet<N>\Services\partmgr\Parameters\SanPolicy` to a DWORD
//! [`SAN_POLICY_OFFLINE`], creating `Parameters`, the `partmgr` key and the
//! value when absent and overwriting the DWORD when present.
//! [`disable_recovery`] takes a BCD store (as produced by
//! [`super::bcd::build`]) and sets element `0x16000009`
//! (`BcdLibraryBoolean_AutoRecoveryEnabled`, `recoveryenabled`) to false
//! (a one-byte inline binary `00`) under
//! `Objects\{default}\Elements\16000009`, creating the element when absent.
//! Both refuse non-`regf` input and missing keys with [`CoreError::InvalidInput`]
//! and refuse honestly (no corruption) when the hive has no room.
//!
//! Limitations, stated plainly: no Windows To Go image has been booted yet;
//! boot acceptance is slices 10-11. The `SYSTEM` shape above is from the
//! Windows 11 24H2 WinPE `SYSTEM` (root `ROOT`, `Select\Current` DWORD `1`).

use super::regf::Hive;
use super::regf::REG_BINARY;
use super::regf::REG_DWORD;
use crate::error::CoreError;
use crate::error::Result;

/// The documented "make internal drives offline" SAN policy value.
pub const SAN_POLICY_OFFLINE: u32 = 4;

/// Element `0x16000009` (`BcdLibraryBoolean_AutoRecoveryEnabled`,
/// `recoveryenabled`): set to false (one zero byte) by [`disable_recovery`].
const ELEMENT_AUTO_RECOVERY_ENABLED: u32 = 0x1600_0009;

/// Ensure the subkey `name` exists under `parent`, cloning the first
/// sibling as the `nk` model when there is one so fresh keys keep the
/// surrounding security descriptor.
fn ensure_child(hive: &mut Hive, parent: usize, name: &[u8]) -> Result<usize> {
    if let Some(found) = hive.find_child(parent, name)? {
        return Ok(found);
    }
    let model = hive.first_child(parent)?;
    hive.add_child_key(parent, name, model)
}

/// Take the applied image's `Windows/System32/config/SYSTEM` hive bytes,
/// read `Select\Current` to learn the current control set number
/// (`ControlSet001`, `ControlSet002`, ...; the value is a DWORD), then set
/// `ControlSet<N>\Services\partmgr\Parameters\SanPolicy` to a DWORD with
/// value [`SAN_POLICY_OFFLINE`], creating `Parameters`, the `partmgr` key
/// and the value when absent and overwriting the DWORD when present.
///
/// Refuses a non-`regf` input, a missing `Select` key, or a missing/invalid
/// `Select\Current` with [`CoreError::InvalidInput`] naming what is missing;
/// refuses honestly (no corruption) when the hive has no room. Returns the
/// rebuilt hive bytes.
pub fn offline_san_policy(system_hive: &[u8]) -> Result<Vec<u8>> {
    let mut hive = Hive::parse(system_hive)?;
    let select_name: &[u8] = b"Select";
    let Some(select) = hive.find_path(&[select_name])? else {
        return Err(CoreError::invalid(
            "system hive has no Select key".to_string(),
        ));
    };
    let current_name: &[u8] = b"Current";
    let Some((vtype, data)) = hive.read_value(select, current_name)? else {
        return Err(CoreError::invalid(
            "system hive has no Select\\Current value".to_string(),
        ));
    };
    if vtype != REG_DWORD {
        return Err(CoreError::invalid(format!(
            "system hive Select\\Current is type {vtype}, expected DWORD 4"
        )));
    }
    let bytes: [u8; 4] = data.as_slice().try_into().map_err(|_| {
        CoreError::invalid(format!(
            "system hive Select\\Current is {} bytes, expected 4-byte DWORD",
            data.len()
        ))
    })?;
    let current = u32::from_le_bytes(bytes);
    if current == 0 || current > 999 {
        return Err(CoreError::invalid(format!(
            "system hive Select\\Current is {current}, expected 1..=999 for ControlSet001..ControlSet999"
        )));
    }
    let controlset = format!("ControlSet{:03}", current);
    let controlset_bytes = controlset.as_bytes();
    let services_name: &[u8] = b"Services";
    let partmgr_name: &[u8] = b"partmgr";
    let parameters_name: &[u8] = b"Parameters";
    let root = hive.root();
    let control = ensure_child(&mut hive, root, controlset_bytes)?;
    let services = ensure_child(&mut hive, control, services_name)?;
    let partmgr = ensure_child(&mut hive, services, partmgr_name)?;
    let parameters = ensure_child(&mut hive, partmgr, parameters_name)?;
    let sanpolicy_name: &[u8] = b"SanPolicy";
    let new_data = SAN_POLICY_OFFLINE.to_le_bytes();
    match hive.read_value(parameters, sanpolicy_name)? {
        Some(_) => hive.set_value(parameters, sanpolicy_name, REG_DWORD, &new_data)?,
        None => {
            hive.add_value(parameters, sanpolicy_name, REG_DWORD, &new_data)?;
        }
    }
    hive.update_checksum()?;
    Ok(hive.to_bytes())
}

/// Take a BCD store (as produced by [`super::bcd::build`]) and set the
/// element `0x16000009` (`BcdLibraryBoolean_AutoRecoveryEnabled`,
/// `recoveryenabled`) to false (a one-byte inline binary `00`) under
/// `Objects\{default}\Elements\16000009`, creating the element when absent.
///
/// Refuses a non-`regf` store, a missing `Objects`, a missing default
/// object, or a missing `Elements` key with [`CoreError::InvalidInput`].
/// Returns the rebuilt store.
pub fn disable_recovery(store: &[u8], default_object: &str) -> Result<Vec<u8>> {
    let mut hive = Hive::parse(store)?;
    let objects_name: &[u8] = b"Objects";
    let Some(objects) = hive.find_child(hive.root(), objects_name)? else {
        return Err(CoreError::invalid(
            "bcd store has no Objects key".to_string(),
        ));
    };
    let Some(default_key) = hive.find_child(objects, default_object.as_bytes())? else {
        return Err(CoreError::invalid(format!(
            "bcd store is missing the default object {default_object}"
        )));
    };
    let elements_name: &[u8] = b"Elements";
    let Some(elements) = hive.find_child(default_key, elements_name)? else {
        return Err(CoreError::invalid(format!(
            "bcd store object {default_object} has no Elements key"
        )));
    };
    let element_id = format!("{:08X}", ELEMENT_AUTO_RECOVERY_ENABLED);
    let element_name = element_id.as_bytes();
    let element_key = match hive.find_child(elements, element_name)? {
        Some(found) => found,
        None => {
            let model = hive.first_child(elements)?;
            hive.add_child_key(elements, element_name, model)?
        }
    };
    let value_name: &[u8] = b"Element";
    let off_data = [0u8];
    match hive.read_value(element_key, value_name)? {
        Some(_) => hive.set_value(element_key, value_name, REG_BINARY, &off_data)?,
        None => {
            hive.add_value(element_key, value_name, REG_BINARY, &off_data)?;
        }
    }
    hive.update_checksum()?;
    Ok(hive.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::bcd::DeviceIdentity;
    use crate::windows::bcd::Firmware;
    use crate::windows::bcd::OBJECT_BOOTMGR;
    use crate::windows::bcd::OBJECT_MEMDIAG;
    use crate::windows::bcd::StoreRequest;
    use crate::windows::bcd::TEMPLATE_LOADER_A194;
    use crate::windows::bcd::TEMPLATE_LOADER_B012;
    use crate::windows::bcd::TEMPLATE_LOADER_CBD9;
    use crate::windows::regf::HBIN_USABLE;
    use crate::windows::regf::HDR_BIN_LENGTH;
    use crate::windows::regf::HDR_CHECKSUM;
    use crate::windows::regf::HDR_ROOT;
    use crate::windows::regf::NONE;

    /// Start a minimal hive: header plus two bins holding a `ROOT` key and
    /// free space, mirroring the `bcd` fixture shape so the tests exercise
    /// the same allocation paths.
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
        buf[0x2004..0x2008].copy_from_slice(&0u32.to_le_bytes());
        buf[0x2008..0x200C].copy_from_slice(&0x1000u32.to_le_bytes());
        // Root `ROOT` key at cell 0x20: 4 + 0x4C + 4 = 84, rounded 88.
        let root_file = 0x1020usize;
        buf[root_file..root_file + 4].copy_from_slice(&(-88i32).to_le_bytes());
        buf[root_file + 4..root_file + 6].copy_from_slice(b"nk");
        buf[root_file + 6..root_file + 8].copy_from_slice(&0x20u16.to_le_bytes());
        buf[root_file + 0x14..root_file + 0x18].copy_from_slice(&NONE.to_le_bytes());
        buf[root_file + 0x20..root_file + 0x24].copy_from_slice(&NONE.to_le_bytes());
        buf[root_file + 0x2C..root_file + 0x30].copy_from_slice(&NONE.to_le_bytes());
        buf[root_file + 0x34..root_file + 0x38].copy_from_slice(&NONE.to_le_bytes());
        buf[root_file + 0x4C..root_file + 0x4E].copy_from_slice(&4u16.to_le_bytes());
        buf[root_file + 0x50..root_file + 0x54].copy_from_slice(b"ROOT");
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

    /// Add a DWORD value under `key`.
    fn add_dword(hive: &mut Hive, key: usize, name: &[u8], value: u32) {
        hive.add_value(key, name, REG_DWORD, &value.to_le_bytes())
            .expect("fixture DWORD must allocate");
    }

    /// Read a DWORD value under `key`, returning (type, value).
    fn read_dword(hive: &Hive, key: usize, name: &[u8]) -> Option<(u32, u32)> {
        let (vtype, data) = hive.read_value(key, name).expect("read must succeed")?;
        let bytes: [u8; 4] = data.as_slice().try_into().expect("DWORD must stay 4 bytes");
        Some((vtype, u32::from_le_bytes(bytes)))
    }

    /// Build a minimal SYSTEM-shaped fixture: `Select\Current = 1` plus
    /// `ControlSet001\Services` with no `partmgr` yet.
    fn system_fixture_without_partmgr() -> Vec<u8> {
        let mut hive = empty_hive();
        let root = hive.root();
        let select = add_key(&mut hive, root, b"Select");
        add_dword(&mut hive, select, b"Current", 1);
        let control = add_key(&mut hive, root, b"ControlSet001");
        add_key(&mut hive, control, b"Services");
        hive.update_checksum().expect("fixture checksum must store");
        hive.into_bytes()
    }

    /// Build a SYSTEM fixture that already carries
    /// `ControlSet001\Services\partmgr\Parameters\SanPolicy = 1`.
    fn system_fixture_with_sanpolicy(value: u32) -> Vec<u8> {
        let mut hive = empty_hive();
        let root = hive.root();
        let select = add_key(&mut hive, root, b"Select");
        add_dword(&mut hive, select, b"Current", 1);
        let control = add_key(&mut hive, root, b"ControlSet001");
        let services = add_key(&mut hive, control, b"Services");
        let partmgr = add_key(&mut hive, services, b"partmgr");
        let parameters = add_key(&mut hive, partmgr, b"Parameters");
        add_dword(&mut hive, parameters, b"SanPolicy", value);
        hive.update_checksum().expect("fixture checksum must store");
        hive.into_bytes()
    }

    /// Look up `ControlSet001\Services\partmgr\Parameters\SanPolicy` in
    /// `bytes`, returning (type, value) when present.
    fn lookup_sanpolicy(bytes: &[u8]) -> Option<(u32, u32)> {
        let hive = Hive::parse(bytes).expect("output must re-parse");
        let root = hive.root();
        let control = hive
            .find_child(root, b"ControlSet001")
            .expect("find control")?;
        let services = hive
            .find_child(control, b"Services")
            .expect("find services")?;
        let partmgr = hive
            .find_child(services, b"partmgr")
            .expect("find partmgr")?;
        let parameters = hive
            .find_child(partmgr, b"Parameters")
            .expect("find parameters")?;
        read_dword(&hive, parameters, b"SanPolicy")
    }

    #[test]
    fn san_policy_offline_value_is_four() {
        assert_eq!(SAN_POLICY_OFFLINE, 4);
    }

    #[test]
    fn offline_san_policy_creates_the_whole_path() {
        let fixture = system_fixture_without_partmgr();
        let out = offline_san_policy(&fixture).expect("missing path must build");
        let got = lookup_sanpolicy(&out).expect("SanPolicy must exist after patch");
        assert_eq!(got, (REG_DWORD, SAN_POLICY_OFFLINE));
        // The rebuilt bytes re-parse (checksum included) and keep Current.
        let hive = Hive::parse(&out).expect("output must re-parse");
        let select = hive
            .find_child(hive.root(), b"Select")
            .expect("find select")
            .expect("Select must survive");
        assert_eq!(read_dword(&hive, select, b"Current"), Some((REG_DWORD, 1)));
    }

    #[test]
    fn offline_san_policy_overwrites_an_existing_dword() {
        let fixture = system_fixture_with_sanpolicy(1);
        assert_eq!(
            lookup_sanpolicy(&fixture),
            Some((REG_DWORD, 1)),
            "fixture must start at 1"
        );
        let out = offline_san_policy(&fixture).expect("existing DWORD must overwrite");
        assert_eq!(
            lookup_sanpolicy(&out),
            Some((REG_DWORD, SAN_POLICY_OFFLINE))
        );
    }

    #[test]
    fn offline_san_policy_refuses_without_current() {
        // A hive with a root but no Select at all.
        let mut hive = empty_hive();
        hive.update_checksum().expect("checksum");
        let bytes = hive.into_bytes();
        let err = offline_san_policy(&bytes).expect_err("no Select must refuse");
        assert!(err.to_string().contains("Select"), "{err}");
        assert!(err.to_string().is_ascii(), "{err}");

        // A hive with Select but no Current value.
        let mut hive = empty_hive();
        let root = hive.root();
        add_key(&mut hive, root, b"Select");
        hive.update_checksum().expect("checksum");
        let bytes = hive.into_bytes();
        let err = offline_san_policy(&bytes).expect_err("no Current must refuse");
        assert!(err.to_string().contains("Current"), "{err}");
        assert!(err.to_string().contains("Select"), "{err}");
        assert!(err.to_string().is_ascii(), "{err}");
    }

    #[test]
    fn offline_san_policy_refuses_non_regf() {
        let mut junk = vec![0u8; 600];
        junk[0..4].copy_from_slice(b"nope");
        let err = offline_san_policy(&junk).expect_err("bad magic must refuse");
        assert!(err.to_string().contains("not a registry hive"), "{err}");
        assert!(err.to_string().is_ascii(), "{err}");
    }

    #[test]
    fn offline_san_policy_refuses_current_of_wrong_type() {
        use crate::windows::regf::REG_SZ;
        use crate::windows::regf::utf16_nul;
        let mut hive = empty_hive();
        let root = hive.root();
        let select = add_key(&mut hive, root, b"Select");
        hive.add_value(select, b"Current", REG_SZ, &utf16_nul("1"))
            .expect("fixture value must allocate");
        hive.update_checksum().expect("checksum");
        let err = offline_san_policy(&hive.into_bytes()).expect_err("wrong type must refuse");
        assert!(err.to_string().contains("Current"), "{err}");
        assert!(err.to_string().contains("DWORD"), "{err}");
        assert!(err.to_string().is_ascii(), "{err}");
    }

    #[test]
    fn offline_san_policy_refuses_current_of_wrong_length() {
        let mut hive = empty_hive();
        let root = hive.root();
        let select = add_key(&mut hive, root, b"Select");
        hive.add_value(select, b"Current", REG_DWORD, &[1, 0])
            .expect("short DWORD must allocate");
        hive.update_checksum().expect("checksum");
        let err = offline_san_policy(&hive.into_bytes()).expect_err("short DWORD must refuse");
        assert!(err.to_string().contains("Current"), "{err}");
        assert!(err.to_string().contains("4-byte DWORD"), "{err}");
        assert!(err.to_string().is_ascii(), "{err}");
    }

    #[test]
    fn offline_san_policy_refuses_out_of_range_current() {
        for current in [0u32, 1000u32] {
            let mut hive = empty_hive();
            let root = hive.root();
            let select = add_key(&mut hive, root, b"Select");
            add_dword(&mut hive, select, b"Current", current);
            hive.update_checksum().expect("checksum");
            let err = offline_san_policy(&hive.into_bytes())
                .expect_err("out-of-range Current must refuse");
            assert!(
                err.to_string().contains(&current.to_string()),
                "must name {current}: {err}"
            );
            assert!(err.to_string().contains("1..=999"), "{err}");
            assert!(err.to_string().is_ascii(), "{err}");
        }
    }

    #[test]
    fn huge_value_refuses_without_corrupting_the_hive() {
        use crate::windows::regf::REG_BINARY;
        let mut hive = empty_hive();
        let root = hive.root();
        let big = vec![0u8; 5000];
        let err = hive
            .add_value(root, b"Big", REG_BINARY, &big)
            .expect_err("oversize value must refuse");
        assert!(err.to_string().is_ascii(), "{err}");
        // The failed allocation must leave a valid hive behind.
        hive.update_checksum().expect("checksum must still store");
        Hive::parse(&hive.to_bytes()).expect("hive must still parse after refusal");
    }

    /// Add an `Elements\{id}` subkey plus its `Element` value, mirroring
    /// the `bcd` fixture pattern.
    fn add_element(hive: &mut Hive, elements: usize, id: &str, vtype: u32, data: &[u8]) {
        let key = add_key(hive, elements, id.as_bytes());
        hive.add_value(key, b"Element", vtype, data)
            .expect("fixture element must allocate");
    }

    /// Build a template-shaped fixture: `System\Objects` with
    /// `{bootmgr}`, both winload loaders and `{memdiag}`, each with an
    /// `Elements` key holding the elements `bcd::build` reads.
    fn template_fixture() -> Vec<u8> {
        use crate::windows::regf::REG_BINARY;
        use crate::windows::regf::REG_SZ;
        use crate::windows::regf::utf16_nul;
        let mut hive = {
            // A `System`-rooted hive for the BCD builder (not the `ROOT`
            // SYSTEM fixture above).
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
            buf[0x2004..0x2008].copy_from_slice(&0u32.to_le_bytes());
            buf[0x2008..0x200C].copy_from_slice(&0x1000u32.to_le_bytes());
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
            let free_file = root_file + 88;
            let free_size = 0x1000u32 - 0x20 - 88;
            buf[free_file..free_file + 4].copy_from_slice(&(free_size as i32).to_le_bytes());
            let free2 = 0x2020usize;
            buf[free2..free2 + 4].copy_from_slice(&(HBIN_USABLE as i32).to_le_bytes());
            let checksum = Hive::header_checksum(&buf).expect("fixture header must checksum");
            buf[HDR_CHECKSUM..HDR_CHECKSUM + 4].copy_from_slice(&checksum.to_le_bytes());
            Hive::parse(&buf).expect("hand-built fixture must parse")
        };
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
        hive.update_checksum().expect("fixture checksum must store");
        hive.into_bytes()
    }

    /// Read one BCD element under `Objects\{object}` in `bytes`.
    fn read_bcd_element(bytes: &[u8], object: &str, id: u32) -> Option<(u32, Vec<u8>)> {
        let hive = Hive::parse(bytes).expect("store must re-parse");
        let objects = hive
            .find_child(hive.root(), b"Objects")
            .expect("find objects")
            .expect("Objects must exist");
        let key = hive
            .find_child(objects, object.as_bytes())
            .expect("find object")?;
        let elements = hive.find_child(key, b"Elements").expect("find elements")?;
        let name = format!("{:08X}", id);
        let element_key = hive
            .find_child(elements, name.as_bytes())
            .expect("find element")?;
        hive.read_value(element_key, b"Element")
            .expect("read element")
    }

    #[test]
    fn disable_recovery_creates_element_and_is_idempotent() {
        let template = template_fixture();
        let request = StoreRequest {
            firmware: Firmware::Uefi,
            identity: DeviceIdentity::Gpt {
                disk_guid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                partition_guid: [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
            },
            description: None,
        };
        let store =
            crate::windows::bcd::build(&template, &request).expect("synthetic build must succeed");
        let loader = crate::windows::bcd::default_object(Firmware::Uefi);
        // No recovery element yet.
        assert!(
            read_bcd_element(&store, loader, ELEMENT_AUTO_RECOVERY_ENABLED).is_none(),
            "fresh store must not carry 16000009 yet"
        );
        let patched = disable_recovery(&store, loader).expect("create must succeed");
        let (vtype, data) = read_bcd_element(&patched, loader, ELEMENT_AUTO_RECOVERY_ENABLED)
            .expect("16000009 must exist after patch");
        assert_eq!(vtype, REG_BINARY);
        assert_eq!(data, vec![0u8]);
        // Calling twice keeps the same single zero byte (idempotent).
        let twice = disable_recovery(&patched, loader).expect("second call must succeed");
        let (vtype2, data2) = read_bcd_element(&twice, loader, ELEMENT_AUTO_RECOVERY_ENABLED)
            .expect("16000009 must survive the second call");
        assert_eq!((vtype2, data2), (REG_BINARY, vec![0u8]));
    }

    #[test]
    fn disable_recovery_refuses_without_objects() {
        let mut hive = empty_hive();
        hive.update_checksum().expect("checksum");
        let bytes = hive.into_bytes();
        let err = disable_recovery(&bytes, "{00000000-0000-0000-0000-000000000000}")
            .expect_err("no Objects must refuse");
        assert!(err.to_string().contains("Objects"), "{err}");
        assert!(err.to_string().is_ascii(), "{err}");
    }

    #[test]
    fn disable_recovery_refuses_without_default_object() {
        let template = template_fixture();
        let missing = "{11111111-2222-3333-4444-555555555555}";
        let err = disable_recovery(&template, missing).expect_err("missing default must refuse");
        assert!(err.to_string().contains(missing), "{err}");
        assert!(err.to_string().is_ascii(), "{err}");
    }

    #[test]
    fn disable_recovery_refuses_without_elements() {
        let mut hive = empty_hive();
        let root = hive.root();
        let objects = add_key(&mut hive, root, b"Objects");
        let default = "{11111111-2222-3333-4444-555555555555}";
        add_key(&mut hive, objects, default.as_bytes());
        hive.update_checksum().expect("checksum");
        let err = disable_recovery(&hive.into_bytes(), default)
            .expect_err("missing Elements must refuse");
        assert!(err.to_string().contains("Elements"), "{err}");
        assert!(err.to_string().contains(default), "{err}");
        assert!(err.to_string().is_ascii(), "{err}");
    }

    /// The real SYSTEM hive from the applied image. Ignored by default:
    /// set `RUFUS_TEST_SYSTEM_HIVE` to the extracted
    /// `Windows/System32/config/SYSTEM` path to run it.
    #[test]
    #[ignore]
    fn real_system_hive_sets_san_policy() {
        let Ok(path) = std::env::var("RUFUS_TEST_SYSTEM_HIVE") else {
            println!("skip: RUFUS_TEST_SYSTEM_HIVE is not set");
            return;
        };
        let bytes = std::fs::read(&path).expect("system hive must read");
        assert_eq!(&bytes[0..4], b"regf");
        let out = offline_san_policy(&bytes).expect("real SYSTEM must patch");
        let (vtype, value) = lookup_sanpolicy(&out).expect("SanPolicy must exist");
        assert_eq!(vtype, REG_DWORD);
        assert_eq!(value, SAN_POLICY_OFFLINE);
    }

    /// The real BCD template from the applied image. Ignored by default:
    /// set `RUFUS_TEST_BCD_TEMPLATE` to the extracted
    /// `Windows/System32/config/BCD-Template` path to run it.
    #[test]
    #[ignore]
    fn real_bcd_template_disables_recovery() {
        let Ok(path) = std::env::var("RUFUS_TEST_BCD_TEMPLATE") else {
            println!("skip: RUFUS_TEST_BCD_TEMPLATE is not set");
            return;
        };
        let template = std::fs::read(&path).expect("template must read");
        assert_eq!(&template[0..4], b"regf");
        let request = StoreRequest {
            firmware: Firmware::Uefi,
            identity: DeviceIdentity::Gpt {
                disk_guid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                partition_guid: [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
            },
            description: None,
        };
        let store =
            crate::windows::bcd::build(&template, &request).expect("real template must build");
        let loader = crate::windows::bcd::default_object(Firmware::Uefi);
        let patched = disable_recovery(&store, loader).expect("real store must patch");
        let (vtype, data) = read_bcd_element(&patched, loader, ELEMENT_AUTO_RECOVERY_ENABLED)
            .expect("16000009 must exist");
        assert_eq!(vtype, REG_BINARY);
        assert_eq!(data, vec![0u8]);
    }
}
