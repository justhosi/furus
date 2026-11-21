use super::*;

#[test]
fn size_drift_detection() {
    let baseline: BTreeMap<String, BaselineEntry> = [
        (
            "furus".to_string(),
            BaselineEntry {
                bytes: 100,
                budget: 3_000_000,
            },
        ),
        (
            "furus-helper".to_string(),
            BaselineEntry {
                bytes: 90,
                budget: 2_500_000,
            },
        ),
        (
            "furus-gui".to_string(),
            BaselineEntry {
                bytes: 80,
                budget: 14_000_000,
            },
        ),
    ]
    .into_iter()
    .collect();
    let full = |furus_bytes: u64| -> BTreeMap<String, u64> {
        [
            ("furus".to_string(), furus_bytes),
            ("furus-helper".to_string(), 90),
            ("furus-gui".to_string(), 80),
        ]
        .into_iter()
        .collect()
    };
    // Exact match passes; growth within the allowance passes and any
    // shrink passes; only growth beyond the allowance fails.
    assert!(check_size_drift(&full(100), &baseline).is_ok());
    assert!(check_size_drift(&full(100 + SIZE_DRIFT_ALLOWANCE), &baseline).is_ok());
    assert!(check_size_drift(&full(100 + SIZE_DRIFT_ALLOWANCE + 1), &baseline).is_err());
    assert!(check_size_drift(&full(99), &baseline).is_ok());
    // Missing baseline entry fails.
    let mut missing = baseline.clone();
    missing.remove("furus-gui");
    assert!(check_size_drift(&full(100), &missing).is_err());
    // Stale budget fails even when the bytes match.
    let mut stale = baseline.clone();
    stale.insert(
        "furus".to_string(),
        BaselineEntry {
            bytes: 100,
            budget: 3_000_001,
        },
    );
    assert!(check_size_drift(&full(100), &stale).is_err());
}
