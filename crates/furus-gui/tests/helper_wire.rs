//! End-to-end helper wire test (S29 slice 3/4).
//!
//! Drives the **compiled** `furus-helper` binary through the GUI's real
//! `PkexecTransport` and consumes its stdout with the real
//! `furus_gui::ipc::EventStream` (which uses `furus_proto::from_jsonl_line`),
//! then feeds every parsed event into the real `furus_gui::run::Run` state
//! machine. No stubs, no mock transport, no second parser.
//!
//! The plan points at an unprivileged, nonexistent device path under
//! `/dev/`, so the helper refuses at `validate::device_node_checks`
//! **before** any device I/O: zero writes, no real block device, and root
//! only inside `unshare -Ur`'s user namespace. The wrapper replaces
//! `pkexec` with `/bin/sh -c` through the documented `with_command` seam;
//! no pkexec, polkit, bus or async runtime is involved.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use furus_core::report::ImageReport;
use furus_gui::ipc::{HelperTransport, PkexecTransport};
use furus_gui::run::{Run, RunState};
use furus_gui::state::{BootSelection, DeviceSelection, GuiState};
use furus_proto::{Completion, Event, ImageKind, ImageRef, Outcome};

static NEXT_CASE: AtomicUsize = AtomicUsize::new(0);

#[test]
fn compiled_helper_refusal_drives_the_gui_parser_and_run_state_machine() {
    // 1. A ready-to-plan form whose device node deliberately does not
    //    exist. The planner trusts the supplied probe facts, so it builds
    //    a valid plan without touching the path; the helper re-checks the
    //    node itself and refuses before any write.
    let case = NEXT_CASE.fetch_add(1, Ordering::Relaxed);
    let suffix = format!("{}-{}", std::process::id(), case);
    let device_path = format!("/dev/furus-qa-missing-{suffix}");
    let image_path = std::env::temp_dir().join(format!("furus-qa-image-{suffix}.iso"));

    let mut gui = GuiState::default();
    gui.device = Some(DeviceSelection {
        identity: format!("QA Missing Device {suffix}"),
        path: device_path.clone(),
        size_bytes: 32_010_928_128,
        sector_size: 512,
        model: Some("QA Missing Device".to_string()),
        serial: Some("QA-MISSING-123".to_string()),
        sysfs: format!("/sys/class/block/furus-qa-missing-{suffix}"),
        mount_summary: "not mounted".to_string(),
    });
    gui.image = Some(BootSelection {
        image: ImageRef {
            path: image_path.to_string_lossy().into_owned(),
            size_bytes: 1_048_576,
            sha256: "0".repeat(64),
            kind: ImageKind::Iso,
        },
        sha256: Some("0".repeat(64)),
        digest_progress: None,
        is_windows: false,
        report: ImageReport::default(),
    });

    // 2. START derives the plan and waits for confirmation.
    let mut run = Run::new();
    run.start(&mut gui).expect("START builds the fixture plan");
    assert_eq!(run.state(), &RunState::Confirming);

    // 3. CONFIRM attaches the hash and hands back the runnable plan.
    let plan = run
        .confirm()
        .expect("CONFIRM attaches the plan hash")
        .clone();
    assert!(matches!(
        run.state(),
        RunState::Running {
            step: None,
            percent: None,
            rate: None,
            eta: None
        }
    ));

    // 4. Find the helper binary next to this test binary; build it once if
    //    the package was not built yet (there is no CARGO_BIN_EXE_* for a
    //    bin from a different package).
    let helper = locate_helper();

    // 5. A user namespace is the only place this test is allowed to be
    //    root. If the kernel/policy forbids it, skip loudly rather than
    //    masking a real failure by falling back to a stub.
    match Command::new("unshare").args(["-Ur", "true"]).status() {
        Ok(status) if status.success() => {}
        other => {
            eprintln!(
                "SKIP compiled_helper_refusal_drives_the_gui_parser_and_run_state_machine: \
                 `unshare -Ur true` is unusable ({other:?}); no unprivileged user namespace"
            );
            return;
        }
    }

    // 6. Replace pkexec with a shell wrapper. With `sh -c SCRIPT name
    //    arg...`, POSIX puts `name` in `$0` and the real helper arguments
    //    in `$@` already (verified: `$0=furus-helper`,
    //    `$@=--plan FILE --progress jsonl`). `shift` would therefore drop
    //    `--plan`, not the literal `furus-helper`, so it must NOT be here.
    let script = format!("exec unshare -Ur {} \"$@\"", shell_quote(&helper));
    let mut transport = PkexecTransport::with_command("/bin/sh", ["-c", script.as_str()]);

    // 7. The transport spawns the wrapper and parses the first event; the
    //    rest arrive through the production GUI JSONL event stream.
    let mut started = transport
        .start(&plan)
        .expect("compiled helper starts through the wrapper");

    // 8. A pre-session refusal emits exactly one Done and no progress or
    //    log lines. Every event is also fed to the run machine.
    let mut events = Vec::new();
    let mut done_count = 0usize;
    for item in started.events.by_ref() {
        let event = item.expect("helper line parses with the production JSONL parser");
        match &event {
            Event::Done(Completion {
                outcome: Outcome::Refused { code, .. },
                ..
            }) => {
                assert_eq!(
                    code, "not_a_block_device",
                    "the missing /dev node is refused before any I/O"
                );
                done_count += 1;
            }
            Event::Done(other) => panic!("unexpected Done outcome: {other:?}"),
            other => panic!("unexpected event kind before the refusal: {other:?}"),
        }
        events.push(event);
    }
    assert_eq!(done_count, 1, "exactly one Done terminates the stream");
    assert_eq!(events.len(), 1, "no progress or log events before the Done");

    // 9. The parsed events, not a hand-made fixture, drive the machine.
    for event in &events {
        run.apply(event, Duration::from_secs(0));
    }

    // 10. The refusal is final and the form is unlocked again.
    assert!(
        matches!(
            run.state(),
            RunState::Finished(Outcome::Refused { code, .. }) if code == "not_a_block_device"
        ),
        "unexpected final state: {:?}",
        run.state()
    );
    assert!(!run.configuration_locked());
}

/// Locate the compiled helper beside this integration-test binary.
///
/// `CARGO_BIN_EXE_furus-helper` is only set for tests in the helper's own
/// package, so derive the path from `current_exe()`:
/// `<target>/<profile>/deps/helper_wire-<hash>` -> `<target>/<profile>`.
fn locate_helper() -> PathBuf {
    let exe = std::env::current_exe().expect("current test binary path");
    let profile_dir = exe
        .parent()
        .and_then(Path::parent)
        .expect("test binary lives in <target>/<profile>/deps");
    let helper = profile_dir.join("furus-helper");
    if helper.is_file() {
        return helper;
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("furus-gui manifest has a workspace root");
    let status = Command::new("cargo")
        .args(["build", "-p", "furus-helper"])
        .current_dir(workspace)
        .status();
    assert!(
        matches!(status, Ok(status) if status.success()),
        "could not build furus-helper from {}: {status:?}",
        workspace.display()
    );
    assert!(
        helper.is_file(),
        "cargo build did not produce {}",
        helper.display()
    );
    helper
}

/// Single-quote a path for `/bin/sh -c`.
fn shell_quote(text: &Path) -> String {
    format!("'{}'", text.to_string_lossy().replace('\'', "'\\''"))
}
