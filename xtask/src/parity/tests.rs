use super::*;

#[test]
fn parity_parses_quoted_notes() {
    // Notes may contain commas inside quotes; they must stay one field.
    let text = "address,name,size,module,kind,disposition,slice,notes\n\
                    0x140001000,FUN_X,8,stdfn,internal,port,S02,\"helper, with comma\"\n";
    let rows = parse_parity_rows(text).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].address, "0x140001000");
    assert_eq!(rows[0].disposition, "port");
    assert_eq!(rows[0].slice, "S02");
}

#[test]
fn parity_check_detects_stale_output() {
    // Identical bytes are fresh; any difference fails.
    assert!(check_regeneration_fresh(b"a,b,c\n", b"a,b,c\n").is_ok());
    assert!(check_regeneration_fresh(b"a,b,c\n", b"a,b,X\n").is_err());
}

#[test]
fn disposition_validation() {
    for valid in ["port", "c-ffi", "crate", "system-tool", "replace", "thunk"] {
        assert!(is_valid_disposition(valid), "{valid} should be valid");
    }
    for invalid in ["", "PORT", "rust", "vendor", "port "] {
        assert!(
            !is_valid_disposition(invalid),
            "{invalid} should be invalid"
        );
    }
}

#[test]
fn slice_validation() {
    assert!(is_valid_slice("S00"));
    assert!(is_valid_slice("S17"));
    assert!(is_valid_slice("S27"));
    assert!(!is_valid_slice(""));
    assert!(!is_valid_slice("S28"));
    assert!(!is_valid_slice("S99"));
    assert!(!is_valid_slice("S1"));
    assert!(!is_valid_slice("17"));
}
