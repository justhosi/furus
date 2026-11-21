use super::*;

use crate::util::repo_root;

#[test]
fn contract_check_passes_for_the_repository() {
    // The committed single source and the packaging files must agree.
    cmd_contract(&repo_root()).unwrap();
}

#[test]
fn contract_const_reads_the_single_source_declarations() {
    let src = "pub const BUS_NAME: &str = \"org.example.Name\";\n\
                   pub const HELPER_DBUS_ARG: &str = \"--dbus\";\n";
    assert_eq!(
        contract_const(src, "BUS_NAME", Path::new("service.rs")).unwrap(),
        "org.example.Name"
    );
    assert_eq!(
        contract_const(src, "HELPER_DBUS_ARG", Path::new("service.rs")).unwrap(),
        "--dbus"
    );
    assert!(contract_const(src, "MISSING", Path::new("service.rs")).is_err());
}
