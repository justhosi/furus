use furus_core::part::plan::LayoutKind;
use furus_core::partition::TableKind;
use furus_proto::{Layout, PLAN_VERSION, Plan, Scheme, Step, Target};

use crate::Exit;
use crate::commands::opener_table_kind;

/// A minimal plan carrying `steps`: the opener derivation only reads
/// steps and `options.scheme`, so device/image facts stay empty.
fn derivation_plan(steps: Vec<Step>) -> Plan {
    Plan {
        version: PLAN_VERSION,
        created_by: "test".to_string(),
        device: furus_proto::DeviceRef {
            path: "/dev/null".to_string(),
            block_device: false,
            size_bytes: None,
            serial: None,
            model: None,
            sysfs: None,
        },
        image: furus_proto::ImageRef {
            path: "image.iso".to_string(),
            size_bytes: 32_780,
            sha256: "0".repeat(64),
            kind: furus_proto::ImageKind::Iso,
        },
        options: furus_proto::Options {
            scheme: Scheme::Mbr,
            target: Target::Dual,
            filesystem: furus_proto::Filesystem::Fat32,
            label: None,
            cluster_bytes: None,
            quick_format: false,
            bad_blocks: false,
            verify: false,
            persistence: false,
            show_all: false,
            confirmed_serial: None,
            msdos_dir: None,
        },
        steps,
        confirm: String::new(),
    }
}

/// The opener derivation follows the steps, not the options: the
/// layout rides on the `Mkpart` step, defaulting to single when no
/// `Mkpart` step is present.
#[test]
fn opener_derivation_reads_table_and_layout_off_the_steps() {
    let plan = derivation_plan(vec![
        Step::Mklabel {
            scheme: Scheme::Mbr,
        },
        Step::Mkpart {
            scheme: Scheme::Mbr,
            layout: Layout::UefiNtfs,
        },
    ]);
    let (table, layout) = match opener_table_kind(&plan) {
        Ok(pair) => pair,
        Err(fail) => panic!("agreeing steps derive: {}", fail.message),
    };
    assert_eq!(table, TableKind::Mbr);
    assert_eq!(layout, LayoutKind::UefiNtfs);

    // No mkpart step at all: the table falls back to the options
    // scheme and the layout to the single default.
    let plan = derivation_plan(vec![Step::Wipe]);
    let (table, layout) = match opener_table_kind(&plan) {
        Ok(pair) => pair,
        Err(fail) => panic!("fallbacks hold: {}", fail.message),
    };
    assert_eq!(table, TableKind::Mbr);
    assert_eq!(layout, LayoutKind::Single);
}

/// Two `Mkpart` steps with different layouts refuse before touching
/// the device, naming both layouts like the scheme refusal names
/// both schemes.
#[test]
fn opener_derivation_refuses_mkpart_layout_disagreement() {
    let plan = derivation_plan(vec![
        Step::Mkpart {
            scheme: Scheme::Mbr,
            layout: Layout::Single,
        },
        Step::Mkpart {
            scheme: Scheme::Mbr,
            layout: Layout::UefiNtfs,
        },
    ]);
    let refused = match opener_table_kind(&plan) {
        Ok(_) => panic!("disagreeing layouts must refuse"),
        Err(fail) => fail,
    };
    assert_eq!(refused.exit, Exit::Usage);
    assert_eq!(refused.kind, "invalid_plan");
    assert!(
        refused.message.contains("single"),
        "names the first layout: {}",
        refused.message
    );
    assert!(
        refused.message.contains("uefi_ntfs"),
        "names the second layout: {}",
        refused.message
    );
}
