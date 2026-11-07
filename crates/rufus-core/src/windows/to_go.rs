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
//!
//! Slice 10 adds the executor ([`install`]): it applies one WIM image onto
//! the mounted data partition, builds and disables recovery on both BCD
//! stores, lays the boot files onto the ESP (UEFI) and the data partition
//! (BIOS), and sets the offline SAN policy on the applied `SYSTEM` hive,
//! in that order. The caller owns both mounts throughout: [`install`]
//! never mounts and never releases either one.
//!
//! Partial failure is sticky, not transactional: a failure after a step
//! leaves the earlier steps' writes on the target — there is no
//! rollback, and the caller must recreate the partitions to retry. A
//! failed in-place `SYSTEM` rewrite can leave that hive truncated,
//! which is why [`install`] stages the patched hive in a temporary
//! file in the same directory and renames it over the original
//! (removing the temporary on failure) instead of truncating in place.

use std::path::Path;
use std::path::PathBuf;

use super::regf::Hive;
use super::regf::REG_BINARY;
use super::regf::REG_DWORD;
use crate::error::CoreError;
use crate::error::Result;
use crate::pipeline::MountedPartition;
use crate::pipeline::event::Reporter;
use crate::windows::bcd;
use crate::windows::boot_files;

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

/// What [`install`] needs: the source WIM and image, the disk identity
/// the BCD device elements encode (already stamped by `Mkpart`), and
/// the boot-loader flavour.
pub struct Request<'a> {
    /// The source `install.wim`.
    pub wim: &'a Path,
    /// The 1-based image index to apply.
    pub image_index: u32,
    /// Disk identity already stamped by `Mkpart`.
    pub identity: bcd::DeviceIdentity,
    /// Edition description for the loader, when known.
    pub description: Option<&'a str>,
    /// Opt into the 2023-signed `_EX` boot loaders (see
    /// [`boot_files::install`]).
    pub use_2023_bootloaders: bool,
}

/// What one [`install`] laid down: the apply counts plus every boot
/// file written, in order (the UEFI set first, then the BIOS set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The apply counts from the reporting tree walk (see
    /// [`crate::windows::apply::apply`]).
    pub applied: crate::windows::apply::Applied,
    /// Every file placed, deterministic order: the UEFI install's
    /// files first, then the BIOS install's, each in the order that
    /// install returned them.
    pub files: Vec<PathBuf>,
}

/// Lay a Windows To Go USB onto two already-mounted partitions: apply
/// the WIM image onto `data`, build both BCD stores from the applied
/// image's own `BCD-Template`, disable recovery on each, copy the boot
/// files onto the ESP (UEFI) and `data` (BIOS), and set the offline SAN
/// policy on the applied `SYSTEM` hive in place.
///
/// The contract, in order:
/// 0. Refuse when both mount roots are the same path, before the WIM
///    is opened or applied ([`boot_files::install`] only catches the
///    shared root after the apply).
/// 1. Open the WIM with [`crate::windows::wim::Wim::open`] and apply
///    the image with [`crate::windows::apply::apply`] (progress and
///    cancellation included; a set probe refuses before touching the
///    target).
/// 2. Read `<data>/Windows/System32/config/BCD-Template`; refuse with
///    [`CoreError::InvalidInput`] naming the path when it is absent or
///    unreadable (a WIM that is not a Windows image). A symlink at the
///    template path refuses without being followed: a crafted WIM
///    could otherwise redirect the read outside the mount roots.
/// 3. Build both stores with [`bcd::build`]: UEFI first (with
///    `identity`), BIOS second.
/// 4. [`disable_recovery`] on each store with [`bcd::default_object`].
/// 5. [`boot_files::install`] the UEFI store (ESP plus `data` as the
///    image root), then the BIOS store with the BIOS install.
/// 6. [`offline_san_policy`] on `<data>/Windows/System32/config/SYSTEM`,
///    written back atomically (a temporary file in the same directory
///    renamed over the original, removed on failure); refuse with
///    [`CoreError::InvalidInput`] naming the path when the hive is
///    absent. A symlink at the hive path refuses without being
///    followed, on the read and on the write back alike: a crafted
///    WIM could otherwise redirect either outside the mount roots.
/// 7. Return the apply counts plus the union of placed files (UEFI
///    then BIOS, in the order the installs return them).
///
/// Partial failure leaves partial writes: a failure after a step
/// leaves the earlier steps' writes on the target — there is no
/// rollback, and the caller must recreate the partitions to retry. A
/// failed in-place `SYSTEM` rewrite can leave that hive truncated;
/// the temporary-plus-rename staging above is what keeps a failed
/// rewrite from truncating the original, while everything already
/// written still stands.
///
/// The mounts are borrowed, never released: the caller mounts both and
/// releases both, mirroring the copy arm's rule. Nothing is ever
/// deleted outside the two mount roots, and every path written derives
/// from `data.path()` or `esp.path()`.
pub fn install(
    data: &mut dyn MountedPartition,
    esp: &mut dyn MountedPartition,
    request: &Request<'_>,
    reporter: &mut dyn Reporter,
    cancelled: &dyn Fn() -> bool,
) -> Result<Installed> {
    // Clone the mount roots once so no borrow of the guards crosses
    // the calls below; every path written later hangs off these two.
    let data_root: PathBuf = data.path().to_path_buf();
    let esp_root: PathBuf = esp.path().to_path_buf();
    // 0. Distinct filesystems first: sharing one root would mix the
    // UEFI and BIOS placements, so refuse before the WIM is opened or
    // applied rather than after the apply like the boot-file layer.
    if data_root == esp_root {
        return Err(CoreError::invalid(format!(
            "esp path {} must differ from the data path {}: they are separate filesystems",
            esp_root.display(),
            data_root.display()
        )));
    }
    // 1. The image first: a malformed WIM refuses before either mount
    // is touched, and a set probe refuses before extraction starts.
    let wim = crate::windows::wim::Wim::open(request.wim)?;
    let applied =
        crate::windows::apply::apply(data, &wim, request.image_index, reporter, cancelled)?;
    // 2. The applied image's own template: absent or unreadable means
    // the WIM was not a Windows image at all. A symlink refuses
    // without being followed (see above).
    let template_path = data_root.join("Windows/System32/config/BCD-Template");
    refuse_symlink(&template_path, "read", "the BCD template")?;
    let template = match std::fs::read(&template_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(CoreError::invalid(format!(
                "applied image has no readable BCD template at {}: refusing a WIM that is not a Windows image",
                template_path.display()
            )));
        }
    };
    // 3. Both stores from the same template, UEFI first.
    let uefi_request = bcd::StoreRequest {
        firmware: bcd::Firmware::Uefi,
        identity: request.identity,
        description: request.description,
    };
    let bios_request = bcd::StoreRequest {
        firmware: bcd::Firmware::Bios,
        identity: request.identity,
        description: request.description,
    };
    let uefi_store = bcd::build(&template, &uefi_request)?;
    let bios_store = bcd::build(&template, &bios_request)?;
    // 4. Recovery off on each store's default loader.
    let uefi_store = disable_recovery(&uefi_store, bcd::default_object(bcd::Firmware::Uefi))?;
    let bios_store = disable_recovery(&bios_store, bcd::default_object(bcd::Firmware::Bios))?;
    // 5. Boot files: the UEFI set onto the ESP, the BIOS set onto the
    // data partition itself.
    let uefi = boot_files::install(
        &data_root,
        &esp_root,
        bcd::Firmware::Uefi,
        &uefi_store,
        request.use_2023_bootloaders,
    )?;
    let bios = boot_files::install(
        &data_root,
        &esp_root,
        bcd::Firmware::Bios,
        &bios_store,
        request.use_2023_bootloaders,
    )?;
    // 6. The SAN policy on the applied SYSTEM hive, staged beside
    // the original and renamed over it. Both the read and the write
    // back refuse a symlink without following it (see above).
    let system_path = data_root.join("Windows/System32/config/SYSTEM");
    refuse_symlink(&system_path, "read", "the SYSTEM hive")?;
    let system = match std::fs::read(&system_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(CoreError::invalid(format!(
                "applied image has no SYSTEM hive at {}: cannot set the offline SAN policy",
                system_path.display()
            )));
        }
        Err(error) => return Err(CoreError::io(&system_path, error)),
    };
    let patched = offline_san_policy(&system)?;
    replace_system_hive(&system_path, &patched)?;
    // 7. The apply counts plus both placements, UEFI then BIOS.
    let mut files = uefi.files;
    files.extend(bios.files);
    Ok(Installed { applied, files })
}

/// Refuse when `path` is a symlink, naming the path: `verb` is
/// `"read"` or `"write"` and `what` names the hive (`"the BCD
/// template"`, `"the SYSTEM hive"`). The check uses
/// [`std::fs::symlink_metadata`] so the link is never followed — a
/// crafted WIM can restore either hive as a symlink to a host path,
/// and following it would read or write outside the mount roots. A
/// missing path is not a symlink: `Ok` lets the caller report the
/// absent file its own way.
fn refuse_symlink(path: &Path, verb: &str, what: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(CoreError::invalid(format!(
            "refusing to {verb} {what} through a symlink at {}: a crafted image must not redirect access outside the mounted partitions",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CoreError::io(path, error)),
    }
}

/// Stage `patched` in a temporary file in the same directory as
/// `path` and rename it over the original, removing the temporary on
/// failure: a failed rewrite never truncates the original in place.
/// The write back refuses a symlink without following it (see
/// [`refuse_symlink`]), so a link swapped in between the read and
/// this write still cannot redirect bytes outside the mount roots —
/// the rename would replace the link itself, but the refusal fires
/// first. The staging file itself is created with `create_new` so a
/// symlink planted at the deterministic `SYSTEM.tmp` name refuses
/// instead of redirecting the write outside the mounts.
fn replace_system_hive(path: &Path, patched: &[u8]) -> Result<()> {
    refuse_symlink(path, "write", "the SYSTEM hive")?;
    let tmp = path.with_extension("tmp");
    let mut staged = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
    {
        Ok(staged) => staged,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(CoreError::invalid(format!(
                "refusing to stage the SYSTEM hive at {}: a crafted image must not redirect writes outside the mounted partition",
                tmp.display()
            )));
        }
        Err(error) => return Err(CoreError::io(&tmp, error)),
    };
    if let Err(error) =
        std::io::Write::write_all(&mut staged, patched).map_err(|error| CoreError::io(&tmp, error))
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    drop(staged);
    if let Err(error) = std::fs::rename(&tmp, path).map_err(|error| CoreError::io(path, error)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::event::VecReporter;
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

    /// Local fake [`MountedPartition`](crate::pipeline::MountedPartition):
    /// a directory path, a fixed `free_bytes` answer, and a counted
    /// `release` the executor must never call (the caller owns both
    /// mounts).
    struct FakeMount {
        path: PathBuf,
        free: u64,
        releases: usize,
    }

    impl FakeMount {
        fn new(path: PathBuf, free: u64) -> Self {
            Self {
                path,
                free,
                releases: 0,
            }
        }
    }

    impl MountedPartition for FakeMount {
        fn path(&self) -> &std::path::Path {
            &self.path
        }

        fn free_bytes(&self) -> Result<u64> {
            Ok(self.free)
        }

        fn release(&mut self) -> Result<()> {
            self.releases = self.releases.saturating_add(1);
            Ok(())
        }
    }

    /// A dummy GPT identity for the executor tests: the device elements
    /// encode whatever the caller stamps, so any fixed GUIDs do.
    fn test_identity() -> DeviceIdentity {
        DeviceIdentity::Gpt {
            disk_guid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            partition_guid: [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
        }
    }

    /// Skip gate (the `skip:` convention): the library probe comes
    /// first, then the `wimlib-imagex` presence probe.
    fn skip_without_backend() -> bool {
        if !wimlib_sys::linked() {
            eprintln!(
                "skip: to go install needs libwim, which this build did not link (wimlib_present is off)"
            );
            return true;
        }
        if std::process::Command::new("wimlib-imagex")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!(
                "skip: to go install needs wimlib-imagex, which this host does not ship (install wimlib and re-run)"
            );
            return true;
        }
        false
    }

    /// Capture the scratch tree at `src` into `dir/cap.wim` with image
    /// name `testimg`. Returns the WIM path.
    fn capture_tree(dir: &Path, src: &std::path::Path) -> PathBuf {
        let wim = dir.join("cap.wim");
        let run = std::process::Command::new("wimlib-imagex")
            .arg("capture")
            .arg(src)
            .arg(&wim)
            .arg("testimg")
            .output()
            .expect("wimlib-imagex capture must spawn past the skip gate");
        assert!(
            run.status.success(),
            "capture failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        wim
    }

    #[test]
    fn install_refuses_a_missing_wim() {
        // No assets and no backend: opening the WIM fails before either
        // mount is touched, with or without libwim linked.
        let root = tempfile::tempdir().expect("scratch dir must create");
        let data_path = root.path().join("data");
        let esp_path = root.path().join("esp");
        std::fs::create_dir_all(&data_path).expect("data dir must create");
        std::fs::create_dir_all(&esp_path).expect("esp dir must create");
        let mut data = FakeMount::new(data_path.clone(), u64::MAX);
        let mut esp = FakeMount::new(esp_path.clone(), u64::MAX);
        let missing = root.path().join("no-such.wim");
        let request = Request {
            wim: &missing,
            image_index: 1,
            identity: test_identity(),
            description: None,
            use_2023_bootloaders: false,
        };
        let mut reporter = VecReporter::new();
        let err = install(&mut data, &mut esp, &request, &mut reporter, &|| false)
            .expect_err("a missing WIM must refuse");
        assert!(err.to_string().is_ascii(), "{err}");
        assert_eq!(
            data.releases, 0,
            "a refused install never releases the data mount"
        );
        assert_eq!(
            esp.releases, 0,
            "a refused install never releases the esp mount"
        );
        assert_eq!(
            std::fs::read_dir(&data_path)
                .expect("data must list")
                .count(),
            0,
            "a refused install writes nothing to data"
        );
        assert_eq!(
            std::fs::read_dir(&esp_path).expect("esp must list").count(),
            0,
            "a refused install writes nothing to the esp"
        );
    }

    #[test]
    fn install_refuses_identical_mount_roots_before_opening_the_wim() {
        // One directory mounted twice: the shared root refuses before
        // the WIM is opened or applied (today `boot_files::install`
        // only catches it after the apply), so neither mount is
        // touched and nothing is written.
        let root = tempfile::tempdir().expect("scratch dir must create");
        let shared = root.path().join("shared");
        std::fs::create_dir_all(&shared).expect("shared dir must create");
        let mut data = FakeMount::new(shared.clone(), u64::MAX);
        let mut esp = FakeMount::new(shared.clone(), u64::MAX);
        let missing = root.path().join("no-such.wim");
        let request = Request {
            wim: &missing,
            image_index: 1,
            identity: test_identity(),
            description: None,
            use_2023_bootloaders: false,
        };
        let mut reporter = VecReporter::new();
        let err = install(&mut data, &mut esp, &request, &mut reporter, &|| false)
            .expect_err("a shared mount root must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains("must differ"), "{text}");
        assert!(text.contains(&shared.display().to_string()), "{text}");
        assert!(text.is_ascii(), "{text}");
        assert_eq!(
            data.releases, 0,
            "a refused install never releases the data mount"
        );
        assert_eq!(
            esp.releases, 0,
            "a refused install never releases the esp mount"
        );
        assert_eq!(
            std::fs::read_dir(&shared)
                .expect("shared must list")
                .count(),
            0,
            "a refused install writes nothing"
        );
    }

    #[test]
    fn system_rewrite_stages_beside_the_original() {
        // The atomic helper, without any backend: a plain file is
        // replaced with the new bytes and no temporary is left
        // behind.
        let root = tempfile::tempdir().expect("scratch dir must create");
        let hive = root.path().join("SYSTEM");
        std::fs::write(&hive, b"original-hive-bytes").expect("hive must write");
        replace_system_hive(&hive, b"patched-hive-bytes").expect("the rewrite must land");
        assert_eq!(
            std::fs::read(&hive).expect("hive must read"),
            b"patched-hive-bytes"
        );
        assert!(
            !root.path().join("SYSTEM.tmp").exists(),
            "the staging temporary must not survive success"
        );
        // A missing parent refuses as I/O and leaves nothing behind.
        let missing = root.path().join("no-such-dir/SYSTEM");
        let err = replace_system_hive(&missing, b"patched").expect_err("a missing parent refuses");
        assert!(matches!(err, CoreError::Io { .. }), "must be Io, got {err}");
        assert!(err.to_string().is_ascii(), "{err}");
        assert!(
            !root.path().join("no-such-dir/SYSTEM.tmp").exists(),
            "a failed staging must leave no temporary"
        );
    }

    #[cfg(unix)]
    #[test]
    fn system_rewrite_refuses_a_symlink_without_writing_through() {
        // A hive path that is a symlink to a host file: the write
        // back refuses naming the link, the host target keeps its
        // bytes, and no temporary is staged.
        let root = tempfile::tempdir().expect("scratch dir must create");
        let outside = root.path().join("host-secret");
        std::fs::write(&outside, b"host-secret-must-survive").expect("outside must write");
        let link = root.path().join("SYSTEM");
        std::os::unix::fs::symlink(&outside, &link).expect("symlink must create");
        let err = replace_system_hive(&link, b"patched").expect_err("a symlinked hive refuses");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains("symlink"), "{text}");
        assert!(text.contains("SYSTEM"), "{text}");
        assert!(
            text.contains(&link.display().to_string()),
            "the refusal names the link path, got {text}"
        );
        assert!(text.is_ascii(), "{text}");
        assert_eq!(
            std::fs::read(&outside).expect("outside must read"),
            b"host-secret-must-survive",
            "nothing is written through the link"
        );
        assert!(
            !root.path().join("SYSTEM.tmp").exists(),
            "a refused rewrite stages no temporary"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("link must stat")
                .file_type()
                .is_symlink(),
            "the refused rewrite leaves the link itself alone"
        );
    }

    #[cfg(unix)]
    #[test]
    fn system_rewrite_refuses_a_symlinked_staging_temporary() {
        // A crafted image restores `SYSTEM.tmp` as a symlink to a host
        // file: staging with `create_new` refuses naming the temporary,
        // the host target keeps its bytes, the link stays a link, and
        // the original hive is untouched.
        let root = tempfile::tempdir().expect("scratch dir must create");
        let outside = root.path().join("host-secret");
        std::fs::write(&outside, b"host-secret-must-survive").expect("outside must write");
        let hive = root.path().join("SYSTEM");
        std::fs::write(&hive, b"original-hive-bytes").expect("hive must write");
        let tmp = root.path().join("SYSTEM.tmp");
        std::os::unix::fs::symlink(&outside, &tmp).expect("symlink must create");
        let err =
            replace_system_hive(&hive, b"patched-hive-bytes").expect_err("a symlinked tmp refuses");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains("SYSTEM.tmp"), "{text}");
        assert!(
            text.contains(&tmp.display().to_string()),
            "the refusal names the staging path, got {text}"
        );
        assert!(
            text.contains("crafted image must not redirect writes outside the mounted partition"),
            "{text}"
        );
        assert!(text.is_ascii(), "{text}");
        assert_eq!(
            std::fs::read(&outside).expect("outside must read"),
            b"host-secret-must-survive",
            "nothing is written through the staging link"
        );
        assert!(
            std::fs::symlink_metadata(&tmp)
                .expect("link must stat")
                .file_type()
                .is_symlink(),
            "the refused staging leaves the link itself alone"
        );
        assert_eq!(
            std::fs::read(&hive).expect("hive must read"),
            b"original-hive-bytes",
            "the refused staging leaves the original hive alone"
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_refuses_a_symlinked_bcd_template() {
        if skip_without_backend() {
            return;
        }
        // The applied tree carries `BCD-Template` as a symlink to a
        // host file: the template read refuses without following the
        // link, so the host bytes are never parsed as a hive and the
        // mounts are never released. A real file (`a.txt`) rides along
        // so the apply's reporting walk still finds a regular file.
        let root = tempfile::tempdir().expect("scratch dir must create");
        let outside = root.path().join("host-secret");
        std::fs::write(&outside, b"host-secret-must-survive").expect("outside must write");
        let src = root.path().join("src");
        let config = src.join("Windows/System32/config");
        std::fs::create_dir_all(&config).expect("config dir must create");
        std::fs::write(src.join("a.txt"), b"not windows\n").expect("scratch file must write");
        std::os::unix::fs::symlink(&outside, config.join("BCD-Template"))
            .expect("symlink must create");
        let wim_path = capture_tree(root.path(), &src);
        let data_path = root.path().join("data");
        let esp_path = root.path().join("esp");
        std::fs::create_dir_all(&data_path).expect("data dir must create");
        std::fs::create_dir_all(&esp_path).expect("esp dir must create");
        let mut data = FakeMount::new(data_path.clone(), u64::MAX);
        let mut esp = FakeMount::new(esp_path, u64::MAX);
        let request = Request {
            wim: &wim_path,
            image_index: 1,
            identity: test_identity(),
            description: None,
            use_2023_bootloaders: false,
        };
        let mut reporter = VecReporter::new();
        let template_path = data_path.join("Windows/System32/config/BCD-Template");
        let err = install(&mut data, &mut esp, &request, &mut reporter, &|| false)
            .expect_err("a symlinked template must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains("symlink"), "{text}");
        assert!(text.contains("BCD-Template"), "{text}");
        assert!(
            text.contains(&template_path.display().to_string()),
            "the refusal names the link path, got {text}"
        );
        assert!(text.is_ascii(), "{text}");
        assert_eq!(
            std::fs::read(&outside).expect("outside must read"),
            b"host-secret-must-survive",
            "nothing is read or written through the link"
        );
        assert!(
            std::fs::symlink_metadata(&template_path)
                .expect("link must stat")
                .file_type()
                .is_symlink(),
            "the refused install leaves the link itself alone"
        );
        assert_eq!(
            data.releases, 0,
            "a refused install never releases the data mount"
        );
        assert_eq!(
            esp.releases, 0,
            "a refused install never releases the esp mount"
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_refuses_a_symlinked_system_hive() {
        if skip_without_backend() {
            return;
        }
        // A Windows-shaped tree with a valid template and boot
        // sources, but `SYSTEM` as a symlink to a host file: the boot
        // files still land (partial failure stands — there is no
        // rollback), then the hive step refuses without following the
        // link, so the host bytes keep their content.
        let root = tempfile::tempdir().expect("scratch dir must create");
        let outside = root.path().join("host-secret");
        std::fs::write(&outside, b"host-secret-must-survive").expect("outside must write");
        let src = root.path().join("src");
        let config = src.join("Windows/System32/config");
        std::fs::create_dir_all(&config).expect("config dir must create");
        std::fs::write(config.join("BCD-Template"), template_fixture())
            .expect("template must write");
        std::os::unix::fs::symlink(&outside, config.join("SYSTEM")).expect("symlink must create");
        std::fs::create_dir_all(src.join("Windows/Boot/EFI")).expect("efi dir must create");
        std::fs::create_dir_all(src.join("Windows/Boot/PCAT")).expect("pcat dir must create");
        std::fs::write(
            src.join("Windows/Boot/EFI/bootmgfw.efi"),
            b"fake-efi-loader",
        )
        .expect("efi loader must write");
        std::fs::write(src.join("Windows/Boot/PCAT/bootmgr"), b"fake-bios-loader")
            .expect("bios loader must write");
        std::fs::write(src.join("Windows/Boot/PCAT/boot.sdi"), b"fake-boot-sdi")
            .expect("boot.sdi must write");
        let wim_path = capture_tree(root.path(), &src);
        let data_path = root.path().join("data");
        let esp_path = root.path().join("esp");
        std::fs::create_dir_all(&data_path).expect("data dir must create");
        std::fs::create_dir_all(&esp_path).expect("esp dir must create");
        let mut data = FakeMount::new(data_path.clone(), u64::MAX);
        let mut esp = FakeMount::new(esp_path, u64::MAX);
        let request = Request {
            wim: &wim_path,
            image_index: 1,
            identity: test_identity(),
            description: None,
            use_2023_bootloaders: false,
        };
        let mut reporter = VecReporter::new();
        let system_path = data_path.join("Windows/System32/config/SYSTEM");
        let err = install(&mut data, &mut esp, &request, &mut reporter, &|| false)
            .expect_err("a symlinked SYSTEM hive must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains("symlink"), "{text}");
        assert!(text.contains("SYSTEM"), "{text}");
        assert!(
            text.contains(&system_path.display().to_string()),
            "the refusal names the link path, got {text}"
        );
        assert!(text.is_ascii(), "{text}");
        assert_eq!(
            std::fs::read(&outside).expect("outside must read"),
            b"host-secret-must-survive",
            "nothing is written through the link"
        );
        assert!(
            std::fs::symlink_metadata(&system_path)
                .expect("link must stat")
                .file_type()
                .is_symlink(),
            "the refused install leaves the link itself alone"
        );
        assert!(
            !data_path
                .join("Windows/System32/config/SYSTEM.tmp")
                .exists(),
            "a refused rewrite stages no temporary"
        );
        assert_eq!(
            data.releases, 0,
            "a refused install never releases the data mount"
        );
        assert_eq!(
            esp.releases, 0,
            "a refused install never releases the esp mount"
        );
    }

    #[test]
    fn install_refuses_a_wim_without_a_windows_template() {
        if skip_without_backend() {
            return;
        }
        // A plain-files WIM: the apply succeeds, then the missing
        // `BCD-Template` refuses as a non-Windows image.
        let root = tempfile::tempdir().expect("scratch dir must create");
        let src = root.path().join("src");
        std::fs::create_dir_all(&src).expect("scratch tree must create");
        std::fs::write(src.join("a.txt"), b"not windows\n").expect("scratch file must write");
        let wim_path = capture_tree(root.path(), &src);
        let data_path = root.path().join("data");
        let esp_path = root.path().join("esp");
        std::fs::create_dir_all(&data_path).expect("data dir must create");
        std::fs::create_dir_all(&esp_path).expect("esp dir must create");
        let mut data = FakeMount::new(data_path.clone(), u64::MAX);
        let mut esp = FakeMount::new(esp_path, u64::MAX);
        let request = Request {
            wim: &wim_path,
            image_index: 1,
            identity: test_identity(),
            description: None,
            use_2023_bootloaders: false,
        };
        let mut reporter = VecReporter::new();
        let template_path = data_path.join("Windows/System32/config/BCD-Template");
        let err = install(&mut data, &mut esp, &request, &mut reporter, &|| false)
            .expect_err("a WIM without a Windows template must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains("BCD-Template"), "{text}");
        assert!(
            text.contains(&template_path.display().to_string()),
            "the refusal names the template path, got {text}"
        );
        assert!(text.is_ascii(), "{text}");
        assert_eq!(
            data.releases, 0,
            "a refused install never releases the data mount"
        );
        assert_eq!(
            esp.releases, 0,
            "a refused install never releases the esp mount"
        );
    }

    #[test]
    fn install_refuses_an_applied_image_without_a_system_hive() {
        if skip_without_backend() {
            return;
        }
        // A Windows-shaped tree (valid template plus boot sources so
        // the boot-file step passes) but no SYSTEM hive: the SAN policy
        // step refuses naming the path.
        let root = tempfile::tempdir().expect("scratch dir must create");
        let src = root.path().join("src");
        let config = src.join("Windows/System32/config");
        std::fs::create_dir_all(&config).expect("config dir must create");
        std::fs::write(config.join("BCD-Template"), template_fixture())
            .expect("template must write");
        std::fs::create_dir_all(src.join("Windows/Boot/EFI")).expect("efi dir must create");
        std::fs::create_dir_all(src.join("Windows/Boot/PCAT")).expect("pcat dir must create");
        std::fs::write(
            src.join("Windows/Boot/EFI/bootmgfw.efi"),
            b"fake-efi-loader",
        )
        .expect("efi loader must write");
        std::fs::write(src.join("Windows/Boot/PCAT/bootmgr"), b"fake-bios-loader")
            .expect("bios loader must write");
        std::fs::write(src.join("Windows/Boot/PCAT/boot.sdi"), b"fake-boot-sdi")
            .expect("boot.sdi must write");
        let wim_path = capture_tree(root.path(), &src);
        let data_path = root.path().join("data");
        let esp_path = root.path().join("esp");
        std::fs::create_dir_all(&data_path).expect("data dir must create");
        std::fs::create_dir_all(&esp_path).expect("esp dir must create");
        let mut data = FakeMount::new(data_path.clone(), u64::MAX);
        let mut esp = FakeMount::new(esp_path, u64::MAX);
        let request = Request {
            wim: &wim_path,
            image_index: 1,
            identity: test_identity(),
            description: None,
            use_2023_bootloaders: false,
        };
        let mut reporter = VecReporter::new();
        let system_path = data_path.join("Windows/System32/config/SYSTEM");
        let err = install(&mut data, &mut esp, &request, &mut reporter, &|| false)
            .expect_err("an image without SYSTEM must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains("SYSTEM"), "{text}");
        assert!(
            text.contains(&system_path.display().to_string()),
            "the refusal names the SYSTEM path, got {text}"
        );
        assert!(text.is_ascii(), "{text}");
        assert!(
            !system_path.exists(),
            "the missing SYSTEM hive is never invented"
        );
        assert_eq!(
            data.releases, 0,
            "a refused install never releases the data mount"
        );
        assert_eq!(
            esp.releases, 0,
            "a refused install never releases the esp mount"
        );
    }

    /// Copy a directory tree (regular files and subdirectories only).
    fn copy_tree(source: &std::path::Path, dest: &std::path::Path) {
        std::fs::create_dir_all(dest).expect("copy dest must create");
        let listing = std::fs::read_dir(source).expect("copy source must list");
        for entry in listing {
            let entry = entry.expect("copy entry must read");
            let kind = entry.file_type().expect("copy entry must stat");
            let target = dest.join(entry.file_name());
            if kind.is_dir() {
                copy_tree(&entry.path(), &target);
            } else if kind.is_file() {
                std::fs::copy(entry.path(), &target).expect("copy file must copy");
            }
        }
    }

    /// Full executor over the real assets. Ignored by default: set
    /// `RUFUS_TEST_WINDOWS_TREE` to the extracted image root (with
    /// `Windows/Boot` beneath it), `RUFUS_TEST_BCD_TEMPLATE` to the
    /// extracted `Windows/System32/config/BCD-Template` path, and
    /// `RUFUS_TEST_SYSTEM_HIVE` to the extracted
    /// `Windows/System32/config/SYSTEM` path to run it.
    #[test]
    #[ignore]
    fn real_windows_tree_installs_end_to_end() {
        if skip_without_backend() {
            return;
        }
        let Ok(tree) = std::env::var("RUFUS_TEST_WINDOWS_TREE") else {
            println!("skip: RUFUS_TEST_WINDOWS_TREE is not set");
            return;
        };
        let tree = PathBuf::from(tree);
        let Ok(template_source) = std::env::var("RUFUS_TEST_BCD_TEMPLATE") else {
            println!("skip: RUFUS_TEST_BCD_TEMPLATE is not set");
            return;
        };
        let template_source = PathBuf::from(template_source);
        let Ok(system_source) = std::env::var("RUFUS_TEST_SYSTEM_HIVE") else {
            println!("skip: RUFUS_TEST_SYSTEM_HIVE is not set");
            return;
        };
        let system_source = PathBuf::from(system_source);
        // The tree is either the image root (with `Windows/Boot`
        // beneath) or the `Boot` directory itself.
        let boot_source = if tree.join("Windows/Boot/EFI").is_dir() {
            tree.join("Windows/Boot")
        } else {
            tree.clone()
        };
        let loader_source = boot_source.join("EFI/bootmgfw.efi");
        assert!(
            loader_source.is_file(),
            "real tree must carry a uefi boot manager at {}",
            loader_source.display()
        );
        let template = std::fs::read(&template_source).expect("template must read");
        assert_eq!(&template[0..4], b"regf");
        let system = std::fs::read(&system_source).expect("system hive must read");
        assert_eq!(&system[0..4], b"regf");

        // A small fake Windows image: the real `Boot` tree plus the
        // real `BCD-Template` and `SYSTEM` hives.
        let work = tempfile::tempdir().expect("scratch dir must create");
        let src = work.path().join("src");
        copy_tree(&boot_source, &src.join("Windows/Boot"));
        let config = src.join("Windows/System32/config");
        std::fs::create_dir_all(&config).expect("config dir must create");
        std::fs::copy(&template_source, config.join("BCD-Template")).expect("template must copy");
        std::fs::copy(&system_source, config.join("SYSTEM")).expect("system must copy");
        let wim_path = capture_tree(work.path(), &src);

        let data_dir = tempfile::tempdir().expect("data scratch must create");
        let esp_dir = tempfile::tempdir().expect("esp scratch must create");
        let mut data = FakeMount::new(data_dir.path().to_path_buf(), u64::MAX);
        let mut esp = FakeMount::new(esp_dir.path().to_path_buf(), u64::MAX);
        let request = Request {
            wim: &wim_path,
            image_index: 1,
            identity: test_identity(),
            description: None,
            use_2023_bootloaders: false,
        };
        let mut reporter = VecReporter::new();
        let installed = install(&mut data, &mut esp, &request, &mut reporter, &|| false)
            .expect("the fake windows image must install");
        // The applied tree carries the fake Windows files.
        let loader_bytes = std::fs::read(&loader_source).expect("real loader must read");
        assert_eq!(
            std::fs::read(data_dir.path().join("Windows/Boot/EFI/bootmgfw.efi"))
                .expect("applied loader must read"),
            loader_bytes,
            "the applied tree must carry the real boot manager"
        );
        assert!(
            data_dir
                .path()
                .join("Windows/System32/config/SYSTEM")
                .is_file(),
            "the applied tree must carry the SYSTEM hive"
        );
        assert!(
            installed.applied.files > 0,
            "the apply must report extracted files"
        );
        assert_eq!(data.releases, 0, "install never releases the data mount");
        assert_eq!(esp.releases, 0, "install never releases the esp mount");
        // The UEFI store lands on the ESP with recovery disabled on the
        // UEFI default loader.
        let uefi_bcd = esp_dir.path().join("EFI/Microsoft/Boot/BCD");
        assert!(uefi_bcd.is_file(), "the uefi store must land on the ESP");
        let uefi_bytes = std::fs::read(&uefi_bcd).expect("uefi store must read");
        let uefi_default = crate::windows::bcd::default_object(Firmware::Uefi);
        assert_eq!(
            read_bcd_element(&uefi_bytes, uefi_default, ELEMENT_AUTO_RECOVERY_ENABLED),
            Some((REG_BINARY, vec![0u8])),
            "the uefi store must carry {{default}}\\16000009 as inline 00"
        );
        // The ESP carries the loader twice, the fonts and the store.
        assert_eq!(
            std::fs::read(esp_dir.path().join("EFI/Microsoft/Boot/bootmgfw.efi"))
                .expect("esp loader must read"),
            loader_bytes
        );
        assert_eq!(
            std::fs::read(esp_dir.path().join("EFI/Boot/BOOTX64.EFI"))
                .expect("esp fallback must read"),
            loader_bytes
        );
        let mut font_names: Vec<PathBuf> = Vec::new();
        let fonts_dir = boot_source.join("Fonts");
        for entry in std::fs::read_dir(&fonts_dir).expect("real fonts must list") {
            let entry = entry.expect("real font entry must read");
            if entry.file_type().expect("real font must stat").is_file() {
                font_names.push(entry.file_name().into());
            }
        }
        assert!(!font_names.is_empty(), "real tree must carry boot fonts");
        font_names.sort();
        for name in &font_names {
            let source_bytes = std::fs::read(fonts_dir.join(name)).expect("real font must read");
            assert_eq!(
                std::fs::read(esp_dir.path().join("EFI/Microsoft/Boot/Fonts").join(name))
                    .expect("placed font must read"),
                source_bytes,
                "font must copy byte for byte"
            );
        }
        // The BIOS store lands on the data partition with recovery
        // disabled on the BIOS default loader.
        let bios_bcd = data_dir.path().join("boot/bcd");
        assert!(bios_bcd.is_file(), "the bios store must land on data");
        let bios_bytes = std::fs::read(&bios_bcd).expect("bios store must read");
        let bios_default = crate::windows::bcd::default_object(Firmware::Bios);
        assert_eq!(
            read_bcd_element(&bios_bytes, bios_default, ELEMENT_AUTO_RECOVERY_ENABLED),
            Some((REG_BINARY, vec![0u8])),
            "the bios store must carry {{default}}\\16000009 as inline 00"
        );
        // The data partition carries the BIOS boot files.
        assert_eq!(
            std::fs::read(data_dir.path().join("bootmgr")).expect("bootmgr must read"),
            std::fs::read(boot_source.join("PCAT/bootmgr")).expect("real bootmgr must read"),
            "data must carry the real bios boot manager"
        );
        let sdi_primary = boot_source.join("PCAT/boot.sdi");
        let sdi_fallback = boot_source.join("DVD/PCAT/boot.sdi");
        let sdi_wanted = if sdi_primary.is_file() {
            &sdi_primary
        } else {
            &sdi_fallback
        };
        assert!(sdi_wanted.is_file(), "real tree must carry a boot.sdi");
        assert_eq!(
            std::fs::read(data_dir.path().join("boot/boot.sdi")).expect("boot.sdi must read"),
            std::fs::read(sdi_wanted).expect("real boot.sdi must read"),
            "data must carry the real boot.sdi"
        );
        // The SAN policy in the applied SYSTEM is offline (4).
        let applied_system = std::fs::read(data_dir.path().join("Windows/System32/config/SYSTEM"))
            .expect("applied SYSTEM must read");
        assert_eq!(
            lookup_sanpolicy(&applied_system),
            Some((REG_DWORD, SAN_POLICY_OFFLINE))
        );
        // The placed files are the UEFI set then the BIOS set, every
        // one under one of the two mount roots.
        assert!(!installed.files.is_empty(), "install must place files");
        let split = installed
            .files
            .iter()
            .position(|file| file.starts_with(data_dir.path()))
            .expect("the bios set must place data files");
        assert!(
            installed.files[..split]
                .iter()
                .all(|file| file.starts_with(esp_dir.path())),
            "the uefi set comes first, all on the ESP: {:?}",
            installed.files
        );
        assert!(
            installed.files[split..]
                .iter()
                .all(|file| file.starts_with(data_dir.path())),
            "the bios set comes second, all on data: {:?}",
            installed.files
        );
        assert_eq!(
            installed.files.last().expect("files must exist"),
            &bios_bcd,
            "the bios store is the last file placed"
        );
        // A pre-cancelled run refuses as cancelled on fresh mounts.
        let fresh_data = tempfile::tempdir().expect("fresh data must create");
        let fresh_esp = tempfile::tempdir().expect("fresh esp must create");
        let mut fresh_data_mount = FakeMount::new(fresh_data.path().to_path_buf(), u64::MAX);
        let mut fresh_esp_mount = FakeMount::new(fresh_esp.path().to_path_buf(), u64::MAX);
        let mut cancelled_reporter = VecReporter::new();
        let err = install(
            &mut fresh_data_mount,
            &mut fresh_esp_mount,
            &request,
            &mut cancelled_reporter,
            &|| true,
        )
        .expect_err("a pre-cancelled run must refuse");
        assert!(
            matches!(err, CoreError::Cancelled),
            "a pre-cancelled run must be Cancelled, got {err}"
        );
        assert_eq!(
            fresh_data_mount.releases, 0,
            "a cancelled run never releases"
        );
        assert_eq!(
            fresh_esp_mount.releases, 0,
            "a cancelled run never releases"
        );
    }
}
