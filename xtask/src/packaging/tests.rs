use super::*;

use crate::util::repo_root;

#[test]
fn parse_ini_accepts_comments_and_rejects_duplicates() {
    let text = "# leading comment\n; another\n[Desktop Entry]\nType=Application\nName = x # not a comment\n";
    let ini = parse_ini(text).unwrap();
    assert_eq!(ini["Desktop Entry"]["Type"], "Application");
    assert_eq!(ini["Desktop Entry"]["Name"], "x # not a comment");

    for bad in [
        "Type=Application\n",   // key before any section
        "[A]\nx=1\nx=2\n",      // duplicate key
        "[A]\nx=1\n[A]\ny=2\n", // duplicate section
        "[A\nx=1\n",            // malformed section header
        "[A]\nno-equals\n",     // malformed key=value
    ] {
        assert!(parse_ini(bad).is_err(), "{bad:?} should be rejected");
    }
}

#[test]
fn finalized_packaging_validates() {
    let packaging = validate_packaging(&repo_root().join("packaging")).unwrap();
    assert_eq!(packaging.texts.len(), PACKAGING_FILES.len());
    assert!(
        packaging
            .get("deb/control")
            .unwrap()
            .contains("Recommends: ntfs-3g")
    );
}

#[test]
fn real_packaging_xml_and_ini_files_validate() {
    let root = repo_root().join("packaging");
    let read = |rel: &str| std::fs::read_to_string(root.join(rel)).unwrap();
    // XML-backed definitions.
    validate_polkit(&read("polkit/org.furuslinux.policy")).unwrap();
    validate_bus_conf(&read("dbus/org.furuslinux.Helper1.conf")).unwrap();
    validate_metainfo(&read("org.furuslinux.Furus.metainfo.xml")).unwrap();
    // INI-backed definitions.
    validate_service(&read("dbus/org.furuslinux.Helper1.service")).unwrap();
    validate_desktop(&read("org.furuslinux.Furus.desktop")).unwrap();
    // Distro metadata tokens.
    validate_deb_control(&read("deb/control")).unwrap();
    validate_rpm_spec(&read("rpm/furus.spec")).unwrap();
    validate_arch_pkgbuild(&read("arch/PKGBUILD")).unwrap();
    // All 11 finalized files exist, including the non-validated payloads.
    assert_eq!(PACKAGING_FILES.len(), 11);
    for rel in PACKAGING_FILES {
        assert!(root.join(rel).is_file(), "missing packaging file {rel}");
    }
}

#[test]
fn malformed_xml_is_rejected() {
    // Unclosed element.
    assert!(validate_polkit("<policyconfig><action id=\"org.furuslinux.write-device\">").is_err());
    // Mismatched closing tag.
    assert!(validate_bus_conf("<busconfig><policy></busconfig>").is_err());
    // Polkit action with the wrong/missing id.
    let no_id = "<policyconfig><action id=\"other\"><defaults>\
                     <allow_any>no</allow_any><allow_inactive>no</allow_inactive>\
                     <allow_active>auth_admin_keep</allow_active></defaults></action></policyconfig>";
    assert!(validate_polkit(no_id).is_err());
    assert!(validate_polkit("<policyconfig/>").is_err());
    // Polkit defaults missing auth_admin_keep (wrong value).
    let wrong_keep = "<policyconfig><action id=\"org.furuslinux.write-device\"><defaults>\
                          <allow_any>no</allow_any><allow_inactive>no</allow_inactive>\
                          <allow_active>yes</allow_active></defaults></action></policyconfig>";
    assert!(validate_polkit(wrong_keep).is_err());
    // Bus config missing the root-owned `own` rule.
    let bus_no_root = "<busconfig><policy context=\"default\">\
                           <deny own=\"org.furuslinux.Helper1\"/>\
                           <allow send_destination=\"org.furuslinux.Helper1\"/>\
                           </policy></busconfig>";
    assert!(validate_bus_conf(bus_no_root).is_err());
    // Metainfo missing the required <id>.
    assert!(
        validate_metainfo("<component type=\"desktop-application\"><name>x</name></component>")
            .is_err()
    );
    // Metainfo with the wrong id.
    assert!(
        validate_metainfo("<component type=\"desktop-application\"><id>wrong</id></component>")
            .is_err()
    );
}

#[test]
fn malformed_ini_is_rejected_by_validators() {
    // Duplicate section, duplicate key and key outside a section all go
    // through parse_ini; the higher-level validators must refuse them too.
    assert!(validate_service("[D-Bus Service]\nName=x\nName=y\n").is_err());
    assert!(validate_service("[D-Bus Service]\nName=x\n[D-Bus Service]\nExec=y\n").is_err());
    assert!(validate_desktop("Exec=furus-gui\n[Desktop Entry]\nType=Application\n").is_err());
    // Missing required keys: Exec in the desktop entry, User in the
    // service. Both otherwise-valid files must still be rejected.
    let no_exec =
        "[Desktop Entry]\nType=Application\nName=x\nIcon=x\nTerminal=false\nCategories=System;\n";
    assert!(validate_desktop(no_exec).is_err());
    let no_user =
        "[D-Bus Service]\nName=org.furuslinux.Helper1\nExec=/usr/libexec/furus-helper --dbus\n";
    assert!(validate_service(no_user).is_err());
    // A wrong Exec value is rejected as well.
    let wrong_exec = "[D-Bus Service]\nName=org.furuslinux.Helper1\nExec=/bin/false\nUser=root\n";
    assert!(validate_service(wrong_exec).is_err());
}
