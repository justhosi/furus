use std::path::PathBuf;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::commands::write_options;

/// `--reset-usb` parses on `write` (absent by default) and reaches
/// [`RunOptions`](furus_core::pipeline::RunOptions) verbatim, with
/// the reference retry policy alongside: the parse half and the
/// plumbing half of the flag, without running a plan.
#[test]
fn write_reset_usb_parses_and_plumbs_to_run_options() {
    let cli = Cli::try_parse_from(["furus", "write", "--plan", "plan.json"])
        .expect("write parses without the flag");
    let Command::Write { plan, reset_usb } = &cli.command else {
        panic!("expected the write subcommand");
    };
    assert_eq!(plan, &PathBuf::from("plan.json"));
    assert!(!*reset_usb);
    assert!(!write_options(false, false, *reset_usb).reset_usb);

    let cli = Cli::try_parse_from(["furus", "write", "--plan", "plan.json", "--reset-usb"])
        .expect("write parses with the flag");
    let Command::Write { reset_usb, .. } = &cli.command else {
        panic!("expected the write subcommand");
    };
    assert!(*reset_usb);
    let options = write_options(true, true, *reset_usb);
    assert!(options.reset_usb);
    assert!(options.verify);
    assert!(options.badblocks);
    // The reference policy (`0x140010a40`) rides along unchanged.
    assert_eq!(options.retries, 3);
    assert_eq!(options.retry_delay, std::time::Duration::from_secs(5));
}
