use super::*;

/// Cancellation maps to exit 6 with kind `cancelled`, bare and
/// through the step wrapper. No message text is matched: the
/// contract is the code plus the kind.
#[test]
fn from_core_maps_cancellation_to_exit_6() {
    let fail = Fail::from_core(CoreError::Cancelled);
    assert_eq!(fail.exit, Exit::Cancelled);
    assert_eq!(fail.exit.code(), 6);
    assert_eq!(fail.kind, "cancelled");
    let fail = Fail::from_core(CoreError::Step {
        step: "write",
        source: Box::new(CoreError::Cancelled),
    });
    assert_eq!(fail.exit, Exit::Cancelled);
    assert_eq!(fail.exit.code(), 6);
    assert_eq!(fail.kind, "cancelled");
}

/// Unimplemented steps map to exit 7 with kind `not_implemented`,
/// bare (the pipeline never wraps this variant). Same terms: code
/// plus kind, no message text.
#[test]
fn from_core_maps_unimplemented_to_exit_7() {
    let fail = Fail::from_core(CoreError::NotImplemented {
        what: "copy of a wim image (the wim reader arrives in a later slice)",
    });
    assert_eq!(fail.exit, Exit::NotImplemented);
    assert_eq!(fail.exit.code(), 7);
    assert_eq!(fail.kind, "not_implemented");
}

/// Verification failures map to exit 4 with kind `verify`, bare
/// and through the step wrapper — a device-integrity failure, not
/// a usage error. Same terms: code plus kind, no message text.
#[test]
fn from_core_maps_verify_to_exit_4() {
    let fail = Fail::from_core(CoreError::Verify {
        message: "first differing byte at offset 3".to_string(),
    });
    assert_eq!(fail.exit, Exit::Io);
    assert_eq!(fail.exit.code(), 4);
    assert_eq!(fail.kind, "verify");
    let fail = Fail::from_core(CoreError::Step {
        step: "write",
        source: Box::new(CoreError::Verify {
            message: "first differing byte at offset 3".to_string(),
        }),
    });
    assert_eq!(fail.exit, Exit::Io);
    assert_eq!(fail.exit.code(), 4);
    assert_eq!(fail.kind, "verify");
}

/// The pre-existing classes are unchanged by the new arms: I/O
/// (bare and step-wrapped) stays exit 4, validation stays exit 1.
#[test]
fn from_core_keeps_io_and_usage_classes() {
    let fail = Fail::from_core(CoreError::io("disk", std::io::Error::other("media error")));
    assert_eq!(fail.exit, Exit::Io);
    assert_eq!(fail.exit.code(), 4);
    assert_eq!(fail.kind, "io");
    let fail = Fail::from_core(CoreError::Step {
        step: "wipe",
        source: Box::new(CoreError::io("disk", std::io::Error::other("media error"))),
    });
    assert_eq!(fail.exit, Exit::Io);
    assert_eq!(fail.kind, "io");
    let fail = Fail::from_core(CoreError::invalid("bad value"));
    assert_eq!(fail.exit, Exit::Usage);
    assert_eq!(fail.exit.code(), 1);
    assert_eq!(fail.kind, "invalid_input");
}
