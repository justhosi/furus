use furus_proto::{Layout, Scheme, Step};

use crate::output::describe_step;

/// The human mkpart line prints scheme and layout in their JSON
/// spellings.
#[test]
fn describe_step_prints_mkpart_scheme_and_layout() {
    let line = describe_step(&Step::Mkpart {
        scheme: Scheme::Gpt,
        layout: Layout::UefiNtfs,
    });
    assert_eq!(line, "mkpart (scheme gpt layout uefi_ntfs)");
    let line = describe_step(&Step::Mkpart {
        scheme: Scheme::Mbr,
        layout: Layout::Single,
    });
    assert_eq!(line, "mkpart (scheme mbr layout single)");
}
