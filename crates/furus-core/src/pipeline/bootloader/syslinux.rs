use crate::boot::Payload;
use crate::boot::Resource;
use crate::boot::syslinux;
use crate::copy::Source as TreeSource;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::fat32::Fat32;
use crate::report::syslinux_banner;

use super::Installed;

/// Syslinux branch, shared by explicit `Syslinux` mode and `Auto`:
/// companions, generated config, then the boot record last.
pub(super) fn install_syslinux(
    source: &dyn TreeSource,
    fat: &mut Fat32,
    located: &syslinux::Located,
    cancelled: &dyn Fn() -> bool,
    load: &dyn Fn(Resource) -> Result<Payload>,
) -> Result<Installed> {
    // Banner scan over the well-known loader names in the located
    // directory, first hit with a parseable banner wins. Two explicit
    // reads is cheap (absent names return `None` without I/O past the
    // listing) and honest: nothing outside this directory is
    // consulted.
    let mut detected = None;
    for name in ["isolinux.bin", "syslinux.bin"] {
        let Some(bytes) = syslinux::read(source, located.dir(), name)? else {
            continue;
        };
        if let Some(version) = syslinux_banner(&bytes) {
            detected = Some(syslinux::Detected {
                version,
                source: format!("{}/{}", located.path(), name),
            });
            break;
        }
    }
    let inventory = syslinux::inventory(source, located.dir())?;
    let has_ldlinux_c32 = inventory.present().contains(&"ldlinux.c32");
    let selection = syslinux::select(detected, has_ldlinux_c32);
    let missing = inventory.required_missing(selection.family());
    if !missing.is_empty() {
        return Err(CoreError::invalid(format!(
            "syslinux {} install needs {} but the image lacks it: refusing before any write",
            selection.family().version(),
            missing.join(", "),
        )));
    }
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let target = located.path();
    let placed = syslinux::install_companions(fat, source, located.dir(), &target)?;
    // The wrapper chains back to the image's own config: prefer the
    // config file the directory actually holds, defaulting to the
    // conventional name when neither is there.
    let cfg_name = if syslinux::read(source, located.dir(), "isolinux.cfg")?.is_some() {
        "isolinux.cfg"
    } else if syslinux::read(source, located.dir(), "syslinux.cfg")?.is_some() {
        "syslinux.cfg"
    } else {
        "isolinux.cfg"
    };
    let config_path = if target == "/" {
        format!("/{cfg_name}")
    } else {
        format!("{target}/{cfg_name}")
    };
    let text = syslinux::config_text(config_path.as_bytes())?;
    syslinux::write_config(fat, &text)?;
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let loader = syslinux::install_payloads_from(fat, selection.family(), load)?;
    // Reference order: the located line prints before the detection
    // (or forcing) line.
    let mut messages: Vec<String> = Vec::new();
    messages.extend(located.messages().iter().cloned());
    messages.extend(selection.messages().iter().cloned());
    messages.extend(placed.cautions.iter().cloned());
    for name in &placed.kept {
        messages.push(format!("  Kept existing '{name}'"));
    }
    Ok(Installed::Syslinux {
        family: selection.family(),
        dir: target,
        stage_bytes: loader.stage_bytes(),
        companions: placed.written,
        kept_companions: placed.kept,
        config_path: "/syslinux.cfg".to_string(),
        messages,
    })
}
