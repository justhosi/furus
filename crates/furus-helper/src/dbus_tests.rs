use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;

use furus_core::hash::hash_file;
use furus_linux::SysfsRoot;
use furus_proto::DeviceRef;
use furus_proto::Event;
use furus_proto::Filesystem;
use furus_proto::ImageKind;
use furus_proto::ImageRef;
use furus_proto::Options;
use furus_proto::PLAN_VERSION;
use furus_proto::Plan;
use furus_proto::Scheme;
use furus_proto::Step;
use furus_proto::Target as Firmware;

use crate::validate;

use super::Authorizer;
use super::BUS_NAME;
use super::ERROR_BUSY;
use super::ERROR_INVALID_PLAN;
use super::ERROR_NOT_AUTHORIZED;
use super::ERROR_UNKNOWN_SESSION;
use super::EVENT_STREAM_VERSION;
use super::EventEmitter;
use super::Handoff;
use super::OBJECT_PATH;
use super::POLKIT_ACTION;
use super::Registry;
use super::ServiceError;
use super::UNKNOWN_PERCENT;
use super::UNKNOWN_TOTAL;
use super::outcome_json;
use super::polkit_disk_write_verdict;
use super::polkit_subject;
use super::progress_args;
use super::to_dbus_error;

// ----------------------------------------------------------------------
// Part 5b: the wire shapes a bus half must not drift from.
// ----------------------------------------------------------------------

#[test]
fn polkit_subject_carries_the_caller_as_a_system_bus_name() {
    let subject = polkit_subject(":1.42");
    assert_eq!(subject.value_signature().to_string(), "(sa{sv})");
    let printed = format!("{subject:?}");
    assert!(printed.contains("system-bus-name"), "{printed}");
    assert!(printed.contains(":1.42"), "{printed}");
}

#[test]
fn outcome_json_pins_all_four_outcomes() {
    assert_eq!(outcome_json(&super::Outcome::Ok), r#"{"outcome":"ok"}"#);
    assert_eq!(
        outcome_json(&super::Outcome::Cancelled),
        r#"{"outcome":"cancelled"}"#
    );
    assert_eq!(
        outcome_json(&super::Outcome::Refused {
            code: "mounted".to_string(),
            message: "device is mounted at /media/x".to_string(),
        }),
        r#"{"outcome":"refused","code":"mounted","message":"device is mounted at /media/x"}"#
    );
    assert_eq!(
        outcome_json(&super::Outcome::Failed {
            code: "io".to_string(),
            message: "boom".to_string(),
        }),
        r#"{"outcome":"failed","code":"io","message":"boom"}"#
    );
}

#[test]
fn dbus_error_mapping_keeps_authorization_denials_distinct() {
    let denied = to_dbus_error(&ServiceError::not_authorized("nope".to_string()));
    assert!(
        matches!(&denied, zbus::fdo::Error::AccessDenied(message) if message == "nope"),
        "{denied:?}"
    );
    let busy = to_dbus_error(&ServiceError::busy("one at a time".to_string()));
    assert!(
        matches!(&busy, zbus::fdo::Error::Failed(message) if message == "org.furuslinux.Error.Busy: one at a time"),
        "{busy:?}"
    );
    let invalid = to_dbus_error(&ServiceError::invalid_plan(
        "confirm_mismatch: x".to_string(),
    ));
    assert!(
        matches!(&invalid, zbus::fdo::Error::Failed(message) if message.starts_with("org.furuslinux.Error.InvalidPlan: confirm_mismatch")),
        "{invalid:?}"
    );
}

// -- the polkit verdict: the gate between a local bus caller and
//    a disk write -----------------------------------------------------

#[test]
fn polkit_disk_write_verdict_pins_the_grant_table() {
    // The rule, and nothing more: only an explicit `true` in the
    // first field authorises a write. The challenge flag stays
    // read-only for the verdict (a prompt nobody answered is
    // polkit's `auth_admin_keep` business) and the details map can
    // never upgrade a `false` into a grant.
    let answered: HashMap<String, String> = HashMap::from([(
        "polkitDetails".to_string(),
        "present-but-advisory".to_string(),
    )]);
    assert!(
        polkit_disk_write_verdict((true, false, HashMap::new())),
        "an explicit yes authorises"
    );
    assert!(
        polkit_disk_write_verdict((true, true, answered.clone())),
        "the challenge flag must not veto a granted verdict"
    );
    assert!(
        !polkit_disk_write_verdict((false, false, HashMap::new())),
        "a plain no denies"
    );
    assert!(
        !polkit_disk_write_verdict((false, true, answered.clone())),
        "a no stays a no with a challenge and non-empty details"
    );
}

// -- the Progress signal mapping (the pure half of the emitter) --------

#[test]
fn progress_args_pass_know_sizes_through_unchanged() {
    let progress = furus_proto::Progress::new(":1.7", 3, "write", 10, Some(10));
    let args = progress_args(&progress);
    assert_eq!(args.session, ":1.7", "unique bus names are already ASCII");
    assert_eq!(args.step, 3);
    assert_eq!(args.op, "write");
    assert_eq!(args.done, 10);
    assert_eq!(args.total, 10, "a known total rides the wire as itself");
    assert_eq!(args.percent, 100, "the derived percent rides verbatim");
}

#[test]
fn progress_args_maps_absent_sizes_to_the_negative_one_sentinels() {
    let progress = furus_proto::Progress::new(":1.7", 0, "wipe", 0, None);
    let args = progress_args(&progress);
    assert_eq!(args.total, UNKNOWN_TOTAL);
    assert_eq!(args.percent, UNKNOWN_PERCENT);
}

#[test]
fn progress_args_saturates_a_u64_max_total_instead_of_collapsing_it() {
    let progress = furus_proto::Progress::new(":1.7", 0, "write", 0, Some(u64::MAX));
    let args = progress_args(&progress);
    assert!(
        args.total > 0,
        "an honest huge total must not read as the unknown sentinel"
    );
    assert_ne!(args.total, UNKNOWN_TOTAL);
    assert_eq!(args.total, i64::MAX, "the saturation target is i64::MAX");
}

#[test]
fn progress_args_saturates_a_step_beyond_u32_instead_of_panicking() {
    // The "a usize-wide plan no real device list can produce" case
    // (see `progress_args`): saturation, no panic, no wrap.
    let progress = furus_proto::Progress::new(":1.7", u32::MAX as usize + 1, "wipe", 0, None);
    let args = progress_args(&progress);
    assert_eq!(args.step, u32::MAX);
}

// ----------------------------------------------------------------------
// Fakes: a fixed authoriser and an in-memory emitter (the bus half's
// polkit/signal seams). Their shape mirrors `progress::VecSink`, which
// serves the same role on the argv path but through the ProgressSink
// seam — the event stream itself is identical.
// ----------------------------------------------------------------------

struct FixedAuthorizer(bool);

impl Authorizer for FixedAuthorizer {
    fn authorize(&self, _caller: &str) -> Result<bool, String> {
        Ok(self.0)
    }
}

/// An authoriser whose check cannot be made (transient "the check
/// itself failed"); `execute` must fail closed on it.
struct FailingAuthorizer(&'static str);

impl Authorizer for FailingAuthorizer {
    fn authorize(&self, _caller: &str) -> Result<bool, String> {
        Err(self.0.to_string())
    }
}

#[derive(Clone)]
struct VecEmitter {
    events: Arc<Mutex<Vec<Event>>>,
}

impl VecEmitter {
    fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn snapshot(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn completions(&self) -> Vec<furus_proto::Completion> {
        self.snapshot()
            .into_iter()
            .filter_map(|event| match event {
                Event::Done(completion) => Some(completion),
                _ => None,
            })
            .collect()
    }
}

impl EventEmitter for VecEmitter {
    fn emit(&self, event: &Event) -> Result<(), String> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event.clone());
        Ok(())
    }
}

// ----------------------------------------------------------------------
// Bounded drain helpers: the worker outlives its `execute`, so every
// follow-up assertion waits on a predicate with a hard deadline
// instead of sleeping blind.
// ----------------------------------------------------------------------

const WAIT_STEP: Duration = Duration::from_millis(10);
const WAIT_STEPS: u32 = 500; // 5 s in 10 ms increments

fn wait_until(what: &str, check: impl Fn() -> bool) {
    for _ in 0..WAIT_STEPS {
        if check() {
            return;
        }
        std::thread::sleep(WAIT_STEP);
    }
    panic!("{what} never happened within 5 s");
}

/// All the stream's `Done` events so far, waiting for at least one.
fn wait_completions(emitter: &VecEmitter) -> Vec<furus_proto::Completion> {
    wait_until("an event Done", || !emitter.completions().is_empty());
    emitter.completions()
}

fn wait_idle(registry: &Registry) {
    wait_until("the service going idle", || registry.is_idle());
}

// ----------------------------------------------------------------------
// Registry assembly: a scratch tempdir as the sessions root (never
// /run/furus-linux), the fixture env, and the caller's authoriser.
// ----------------------------------------------------------------------

fn registry_with(
    env: validate::Env,
    authorization: Arc<dyn Authorizer>,
    sessions: &tempfile::TempDir,
) -> (Registry, VecEmitter) {
    let emitter = VecEmitter::new();
    let registry = Registry::new(
        sessions.path().to_path_buf(),
        env,
        authorization,
        Arc::new(emitter.clone()),
    );
    (registry, emitter)
}

fn execute_json(plan: &Plan) -> String {
    serde_json::to_string(plan).expect("a test-built plan serialises")
}

// ----------------------------------------------------------------------
// Fixtures: a copied subset of `validate::tests::Fixture` — that
// module is private, so its helpers are unreachable from here; the
// same seed shape (synthetic sysfs stick, sparse device stand-in,
// sparse image, signed plan) is required to make `validate` accept
// a plan hermetically. Uses no root and no real device.
// ----------------------------------------------------------------------

/// The device-tree chain every seeded stick links in at.
const STICK_CHAIN: &str = "devices/pci/usb1/1-2/1-2:1.0/host1/target1:0:0/6:0:0:0";
/// The whole disk's kernel name (and the plan's `/dev/<name>`).
const NAME: &str = "sdb";
const DISK_DEVNUM: &str = "8:16";
const PART_DEVNUM: &str = "8:17";
/// sysfs `size` is in 512-byte units regardless of media geometry.
const SECTOR: u64 = 512;
const STICK_UNITS: u64 = 8192; // 4 MiB of synthetic stick
const STICK_BYTES: u64 = STICK_UNITS * SECTOR;
/// The image the samples describe: 1.5 MiB, well inside the stick.
const IMAGE_LEN: u64 = 1_572_864;
/// The stick fixture's serial (rides into show-all tests).
const SERIAL: &str = "SER123";

struct Fixture {
    _scratch: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let root = scratch.path().to_path_buf();
        Self {
            _scratch: scratch,
            root,
        }
    }

    fn write_text(&self, rel: &str, content: &str) -> PathBuf {
        let path = self.root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("fixture parent directories");
        }
        fs::write(&path, content).unwrap_or_else(|err| panic!("seed {rel}: {err}"));
        path
    }

    fn symlink(&self, target: &Path, link: &str) {
        if let Some(parent) = self.root.join(link).parent() {
            fs::create_dir_all(parent).unwrap_or_else(|err| panic!("link dirs: {err}"));
        }
        let link_path = self.root.join(link);
        if let Ok(meta) = std::fs::symlink_metadata(&link_path) {
            assert!(
                meta.file_type().is_symlink(),
                "refusing to overwrite a real file at {link}"
            );
            std::fs::remove_file(&link_path)
                .unwrap_or_else(|err| panic!("drop stale link {link}: {err}"));
        }
        std::os::unix::fs::symlink(target, &link_path)
            .unwrap_or_else(|err| panic!("link {link}: {err}"));
    }

    /// A sparse stand-in or image file: `len` zero bytes on disk.
    fn sparse(&self, rel: &str, len: u64) -> PathBuf {
        let path = self.root.join(rel);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap_or_else(|err| panic!("sparse {rel}: {err}"));
        file.set_len(len)
            .unwrap_or_else(|err| panic!("length {rel}: {err}"));
        path
    }

    /// Seed the synthetic stick exactly like live sysfs: the S04
    /// chain (`devices/<chain>/block/<name>`), device identity on
    /// the four-up USB node, and class/block sibling links whose
    /// partitions carry the `partition` attribute.
    fn seed_stick(&self, removable: bool) {
        let real = format!("{STICK_CHAIN}/block/{NAME}");
        self.write_text(&format!("{real}/size"), &STICK_UNITS.to_string());
        self.write_text(
            &format!("{real}/removable"),
            if removable { "1" } else { "0" },
        );
        self.write_text(&format!("{real}/ro"), "0");
        self.write_text(&format!("{real}/dev"), DISK_DEVNUM);
        self.write_text(&format!("{STICK_CHAIN}/vendor"), "SanDisk");
        self.write_text(&format!("{STICK_CHAIN}/model"), "Test Stick");
        self.write_text(&format!("{STICK_CHAIN}/serial"), SERIAL);
        let part = format!("{real}/{NAME}1");
        self.write_text(&format!("{part}/size"), "6144");
        self.write_text(&format!("{part}/dev"), PART_DEVNUM);
        self.write_text(&format!("{part}/partition"), "1");

        self.symlink(&self.root.join(STICK_CHAIN), &format!("{real}/device"));
        self.symlink(&self.root.join(&real), &format!("class/block/{NAME}"));
        self.symlink(&self.root.join(&part), &format!("class/block/{NAME}1"));
    }

    /// A mountinfo file carrying one extra foreign line (never the
    /// fixture's own devnums, so the seeded stick is unmounted).
    fn foreign_mountinfo(&self) -> PathBuf {
        self.write_text(
            "mountinfo.tsv",
            "1 0 252:0 / / rw,relatime - ext4 /dev/simroot rw\n",
        )
    }

    /// A `/proc/swaps` file with the header row and nothing on it.
    fn empty_swaps(&self) -> PathBuf {
        self.write_text("swaps.tsv", "Filename Type Size Used Priority\n")
    }

    /// The full test window for `validate`: fixture sysfs, fixture
    /// tables and the regular-file stand-in that plays the device
    /// node (`Env::device_file`).
    fn env(&self, stand_in: &Path) -> validate::Env {
        validate::Env {
            sysfs: SysfsRoot::new(self.root.clone()),
            mountinfo: Some(self.foreign_mountinfo()),
            swaps: Some(self.empty_swaps()),
            device_file: Some(stand_in.to_path_buf()),
        }
    }

    /// A plan for the seeded stick (the canonical good-path steps
    /// of the CLI plan, starting with a `Wipe`).
    fn plan_for(&self, image: &Path, image_len: u64, sha: &str) -> Plan {
        Plan {
            version: PLAN_VERSION,
            created_by: "furus-helper tests".to_string(),
            device: DeviceRef {
                path: format!("/dev/{NAME}"),
                block_device: true,
                size_bytes: Some(STICK_BYTES),
                serial: Some(SERIAL.to_string()),
                model: Some("Test Stick".to_string()),
                sysfs: Some(format!("/sys/class/block/{NAME}")),
            },
            image: ImageRef {
                path: image.display().to_string(),
                size_bytes: image_len,
                sha256: sha.to_string(),
                kind: ImageKind::Raw,
            },
            options: Options {
                scheme: Scheme::Mbr,
                target: Firmware::Uefi,
                filesystem: Filesystem::Fat32,
                label: Some("FURUS".to_string()),
                cluster_bytes: Some(32768),
                quick_format: true,
                bad_blocks: false,
                verify: false,
                persistence: false,
                show_all: false,
                confirmed_serial: None,
                msdos_dir: None,
            },
            steps: vec![
                Step::Wipe,
                Step::Mklabel {
                    scheme: Scheme::Mbr,
                },
                Step::Mkpart {
                    scheme: Scheme::Mbr,
                    layout: furus_proto::Layout::Single,
                },
                Step::Mkfs {
                    filesystem: Filesystem::Fat32,
                    label: Some("FURUS".to_string()),
                    cluster_bytes: Some(32768),
                    quick: true,
                },
                Step::Write {
                    mode: furus_proto::WriteMode::Dd,
                },
                Step::Bootloader {
                    mode: furus_proto::BootloaderMode::Auto,
                },
                Step::Finalize,
            ],
            confirm: String::new(),
        }
    }

    /// Sparse image of `len` zero bytes plus its SHA-256.
    fn image(&self, rel: &str, len: u64) -> (PathBuf, String) {
        let path = self.sparse(rel, len);
        let sha = hash_file(&path).expect("image hashes");
        (path, sha)
    }

    /// The canonical good case: a clean removable stick, blank
    /// device bytes, an image the plan describes exactly.
    fn good(&self, removable: bool) -> (Plan, validate::Env, PathBuf) {
        self.seed_stick(removable);
        let device = self.sparse("device.img", STICK_BYTES);
        let (image, sha) = self.image("image.img", IMAGE_LEN);
        let plan = signed(self.plan_for(&image, IMAGE_LEN, &sha));
        let env = self.env(&device);
        (plan, env, device)
    }
}

/// A plan whose confirm hash is freshly recomputed from its own
/// contents (the CLI's contract).
fn signed(mut plan: Plan) -> Plan {
    plan.confirm = plan
        .confirm()
        .expect("tests build JSON-native plans that always serialise");
    plan
}

/// The good plan pared to a single `Finalize`: the only shape the
/// placeholder executor runs to `Ok`.
fn finalize_only(mut plan: Plan) -> Plan {
    plan.steps = vec![Step::Finalize];
    signed(plan)
}

// -- pinned machine-facing strings -----------------------------------

#[test]
fn wire_names_are_pinned_for_the_bus_half() {
    assert_eq!(BUS_NAME, "org.furuslinux.Helper1");
    assert_eq!(OBJECT_PATH, "/org/furuslinux/Helper1");
    assert_eq!(POLKIT_ACTION, "org.furuslinux.write-device");
    assert_eq!(ERROR_NOT_AUTHORIZED, "org.furuslinux.Error.NotAuthorized");
    assert_eq!(ERROR_BUSY, "org.furuslinux.Error.Busy");
    assert_eq!(ERROR_UNKNOWN_SESSION, "org.furuslinux.Error.UnknownSession");
    assert_eq!(ERROR_INVALID_PLAN, "org.furuslinux.Error.InvalidPlan");
    // CARGO-LOCKED: the stream version the `Done` events must carry.
    assert_eq!(EVENT_STREAM_VERSION, 1);
}

// -- authorisation ---------------------------------------------------

#[test]
fn denied_authorization_runs_nothing_and_leaves_the_service_idle() {
    let fixture = Fixture::new();
    let (plan, env, _device) = fixture.good(true);
    let sessions = tempfile::tempdir().expect("sessions root");
    let (registry, _emitter) = registry_with(env, Arc::new(FixedAuthorizer(false)), &sessions);

    let refused = registry
        .execute("com.example.gui", &execute_json(&plan))
        .expect_err("an unauthorized caller is refused");
    assert_eq!(refused.code(), ERROR_NOT_AUTHORIZED);
    assert!(
        refused.to_string().contains(POLKIT_ACTION),
        "the message names the missing action: {refused}"
    );
    assert!(registry.is_idle(), "a refused caller holds no claim");
    assert_eq!(
        fs::read_dir(sessions.path())
            .expect("the sessions root exists (tempdir made it)")
            .count(),
        0,
        "an unauthorized caller's plan never reached the sessions root"
    );
}

#[test]
fn a_failing_authorizer_check_fails_closed() {
    let fixture = Fixture::new();
    let (plan, env, _device) = fixture.good(true);
    let sessions = tempfile::tempdir().expect("sessions root");
    let (registry, _emitter) = registry_with(
        env,
        Arc::new(FailingAuthorizer("the audit bus refused to answer")),
        &sessions,
    );

    let refused = registry
        .execute("com.example.gui", &execute_json(&plan))
        .expect_err("a failed check is never a grant");
    assert_eq!(refused.code(), ERROR_NOT_AUTHORIZED);
    let message = refused.to_string();
    assert!(
        message.contains("itself failed"),
        "the message says the check failed: {message}"
    );
    assert!(
        message.contains("the audit bus refused to answer"),
        "the check's own detail is reported: {message}"
    );
    assert_eq!(
        fs::read_dir(sessions.path())
            .expect("the sessions root exists (tempdir made it)")
            .count(),
        0,
        "the fail-closed refusal never touched the sessions root"
    );
    assert!(registry.is_idle(), "the fail-closed refusal holds no claim");
}

// -- the busy claim --------------------------------------------------

#[test]
fn a_running_session_keeps_the_service_busy() {
    let fixture = Fixture::new();
    let (good, _env, _) = fixture.good(true);
    let plan = finalize_only(good);
    let sessions = tempfile::tempdir().expect("sessions root");
    let (registry, emitter) = registry_with(_env, Arc::new(FixedAuthorizer(true)), &sessions);

    // Park the worker between "session exists" and "plan starts": the
    // claim is provably held while the test calls again (see
    // `install_run_pause`; the placeholder executor would finish a
    // Finalize-only run in microseconds, with no real pause).
    let barrier = Arc::new(Barrier::new(2));
    let parked = barrier.clone();
    registry.install_run_pause(Some(Arc::new(move || {
        parked.wait();
    })));

    let first = registry
        .execute("com.example.gui", &execute_json(&plan))
        .expect("the first run claims the service");
    assert!(
        registry.running().as_deref() == Some(first.as_str()),
        "the parked run's claim names its session id"
    );
    assert!(!registry.is_idle());

    let second = registry
        .execute("com.example.gui", "{}")
        .expect_err("a claimed service refuses a second run");
    assert_eq!(second.code(), ERROR_BUSY);
    assert!(
        second.to_string().contains("another session"),
        "the message names the condition: {second}"
    );

    // Release the worker; the Finalize-only plan then runs to `Ok`
    // (never declined, never cancelled) and frees its claim.
    barrier.wait();
    wait_idle(&registry);
    assert_eq!(registry.running(), None);

    let completions = wait_completions(&emitter);
    assert_eq!(completions.len(), 1, "exactly one terminal event");
    assert_eq!(completions[0].session, first, "the id is echoed");
    assert_eq!(completions[0].outcome, furus_proto::Outcome::Ok);
}

// -- plan refusals -----------------------------------------------------

#[test]
fn malformed_plan_json_refuses_and_leaves_the_service_idle() {
    let fixture = Fixture::new();
    let (_plan, env, _device) = fixture.good(true);
    let sessions = tempfile::tempdir().expect("sessions root");
    let (registry, _emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

    let refused = registry
        .execute("com.example.gui", "{oops")
        .expect_err("rot JSON refuses");
    assert_eq!(refused.code(), ERROR_INVALID_PLAN);
    assert!(
        refused.to_string().contains("not valid JSON"),
        "the message says what is wrong: {refused}"
    );
    assert!(
        registry.is_idle(),
        "the claim is released before the error returns"
    );
}

#[test]
fn a_tampered_confirm_refuses_naming_the_validator_code() {
    let fixture = Fixture::new();
    let (mut plan, env, _device) = fixture.good(true);
    plan.confirm = format!("sha256:{}", "0".repeat(64)); // any tamper the recompute maths
    let sessions = tempfile::tempdir().expect("sessions root");
    let (registry, _emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

    let refused = registry
        .execute("com.example.gui", &execute_json(&plan))
        .expect_err("an integrity refusal is the service's InvalidPlan");
    assert_eq!(refused.code(), ERROR_INVALID_PLAN);
    assert!(
        refused.to_string().contains("confirm_mismatch"),
        "the validator's rule code is carried in the message: {refused}"
    );
    assert!(
        registry.is_idle(),
        "the claim is released before the error returns"
    );
}

// -- cancel ------------------------------------------------------------

#[test]
fn cancel_of_an_unknown_or_blank_id_refuses() {
    let fixture = Fixture::new();
    let (_plan, env, _device) = fixture.good(true);
    let sessions = tempfile::tempdir().expect("sessions root");
    let (registry, _emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

    for id in ["deadbeefdeadbeefdeadbeefdeadbeef", "", "   \t"] {
        let refused = registry
            .cancel("com.example.gui", id)
            .expect_err("nothing under this id runs");
        assert_eq!(
            refused.code(),
            ERROR_UNKNOWN_SESSION,
            "cancelling {id:?} on an idle service"
        );
    }
    assert!(registry.is_idle());
}

#[test]
fn a_foreign_caller_cannot_cancel_and_learns_nothing_of_the_run() {
    let fixture = Fixture::new();
    let (good, env, _device) = fixture.good(true);
    let plan = finalize_only(good);
    let sessions = tempfile::tempdir().expect("sessions root");
    let (registry, emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

    let barrier = Arc::new(Barrier::new(2));
    let parked = barrier.clone();
    registry.install_run_pause(Some(Arc::new(move || {
        parked.wait();
    })));

    let id = registry
        .execute("com.example.gui", &execute_json(&plan))
        .expect("a valid plan is accepted immediately");

    // A second bus connection (or plain local user) knows the id
    // from /run and tries to abort: refused, with the same
    // sentence a wrong id would draw — nothing leaks about whose
    // run it is.
    let refused = registry
        .cancel("com.example.other", &id)
        .expect_err("another caller cannot cancel the run");
    assert_eq!(refused.code(), ERROR_UNKNOWN_SESSION);
    assert_eq!(
        refused.to_string(),
        format!("no session {id} is running (it never started or has already finished)"),
        "the refusal is indistinguishable from a wrong id"
    );
    assert!(
        registry.running().as_deref() == Some(id.as_str()),
        "the run kept its claim and owner"
    );

    // The run was untouched by the foreign cancel: released
    // unchecked, it reaches Ok, not Cancelled.
    barrier.wait();
    wait_idle(&registry);
    let completions = wait_completions(&emitter);
    assert_eq!(completions.len(), 1, "exactly one Done");
    assert_eq!(completions[0].session, id);
    assert_eq!(
        completions[0].outcome,
        furus_proto::Outcome::Ok,
        "the foreign cancel never reached the run"
    );
}

// -- the run's own stream ----------------------------------------------

#[test]
fn a_finalize_only_plan_runs_ok_and_cleans_the_session() {
    let fixture = Fixture::new();
    let (good, env, _device) = fixture.good(true);
    let plan = finalize_only(good);
    let sessions = tempfile::tempdir().expect("sessions root");
    let (registry, emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

    let id = registry
        .execute("com.example.gui", &execute_json(&plan))
        .expect("a valid plan is accepted immediately");
    assert_eq!(id.len(), 32, "the id is a 32-hex session id");

    wait_idle(&registry);
    let events = emitter.snapshot();
    let completions = wait_completions(&emitter);
    assert_eq!(completions.len(), 1, "exactly one Done: {events:#?}");
    assert_eq!(completions[0].session, id);
    assert_eq!(completions[0].version, EVENT_STREAM_VERSION);
    assert_eq!(completions[0].outcome, furus_proto::Outcome::Ok);

    // The loop's grammar: at least one Progress and one Log, every
    // event echoing the session id.
    let mut progress = false;
    let mut log = false;
    for event in &events {
        match event {
            furus_proto::Event::Progress(p) => {
                progress = true;
                assert_eq!(p.session, id);
            }
            furus_proto::Event::Log(l) => {
                log = true;
                assert_eq!(l.session, id);
            }
            furus_proto::Event::Done(_) => {}
        }
    }
    assert!(progress && log, "the stream moved and spoke: {events:#?}");

    // The session is gone, lock and directory, root itself left
    // standing: nothing persists under the sessions root.
    assert!(
        !sessions.path().join(&id).exists(),
        "the session directory is removed with the run"
    );
    assert_eq!(
        fs::read_dir(sessions.path())
            .expect("the sessions root exists")
            .count(),
        0,
        "no .lock, no session directory, nothing but the root"
    );
}

#[test]
fn cancel_mid_run_reports_cancelled_and_frees_the_service() {
    let fixture = Fixture::new();
    let (good, env, _device) = fixture.good(true);
    let plan = finalize_only(good);
    let sessions = tempfile::tempdir().expect("sessions root");
    let (registry, emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

    let barrier = Arc::new(Barrier::new(2));
    let parked = barrier.clone();
    registry.install_run_pause(Some(Arc::new(move || {
        parked.wait();
    })));

    let id = registry
        .execute("com.example.gui", &execute_json(&plan))
        .expect("a valid plan is accepted immediately");

    // The worker is parked with its claim open: the cancel lands on
    // a run the service genuinely holds (the S06 executor has no
    // mid-step pause; the step loop's very-first check is the
    // earliest real stop, and it keeps the same `Cancelled`
    // contract).
    registry
        .cancel("com.example.gui", &id)
        .expect("the claimed run is cancellable");
    barrier.wait(); // release the worker; the loop's cancel check fires
    wait_idle(&registry);

    let completions = wait_completions(&emitter);
    assert_eq!(completions.len(), 1, "the cancelled run's own Done");
    assert_eq!(completions[0].session, id);
    assert_eq!(
        completions[0].outcome,
        furus_proto::Outcome::Cancelled,
        "the cancellation is the run's outcome"
    );

    // A cancel for a session that already finished refuses now.
    assert_eq!(
        registry
            .cancel("com.example.gui", &id)
            .expect_err("the run is over")
            .code(),
        ERROR_UNKNOWN_SESSION
    );

    // The freed service accepts the next run, which completes Ok.
    registry.install_run_pause(None);
    let second = registry
        .execute("com.example.gui", &execute_json(&plan))
        .expect("the freed claim is fresh");
    wait_idle(&registry);
    let completions = emitter.completions();
    assert_eq!(completions.len(), 2, "one Done per run: {completions:#?}");
    assert_eq!(
        completions[1].session, second,
        "the second run's own terminal event"
    );
    assert_eq!(completions[1].outcome, furus_proto::Outcome::Ok);
}

#[test]
fn a_wiped_plan_reports_a_failed_done_from_the_placeholder_executor() {
    let fixture = Fixture::new();
    // The good plan starts with `Wipe`: validation passes (rules
    // carry), the placeholder executor refuses the step.
    let (plan, env, _device) = fixture.good(true);
    let sessions = tempfile::tempdir().expect("sessions root");
    let (registry, emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

    let id = registry
        .execute("com.example.gui", &execute_json(&plan))
        .expect("a valid plan is accepted; its run may still fail");
    wait_idle(&registry);

    let completions = wait_completions(&emitter);
    assert_eq!(completions.len(), 1, "exactly one Done");
    assert_eq!(completions[0].session, id);
    assert_eq!(
        completions[0].outcome,
        furus_proto::Outcome::Failed {
            code: "unsupported".to_string(),
            message: "step 'wipe' needs the S07 pipeline".to_string(),
        },
        "the placeholder executor's refusal is the run's outcome"
    );
    assert!(
        emitter
            .snapshot()
            .iter()
            .any(|event| matches!(event, furus_proto::Event::Progress(_))),
        "the wipe step reported progress before the refusal"
    );
    assert!(registry.is_idle());
}

// -- the Handoff (the one-shot accept bridge) ----------------------------

#[test]
fn handoff_complete_before_wait_returns_the_value() {
    // The slot-already-set path: the worker answered before the
    // waiter ever parked, so `wait` returns without blocking.
    let handoff = Handoff::new();
    handoff.complete(41u32);
    let got = zbus::block_on(handoff.wait());
    assert_eq!(got, 41u32, "an answer published before waiting is returned");
}

/// Wait for a [`Handoff`] with a hard bound: the wait runs on a
/// spawned thread and the answer rides an `mpsc` channel, so a lost
/// wake fails fast instead of hanging the harness until it kills
/// the test. The bound (seconds) is far above the real wait
/// (milliseconds).
fn wait_handoff<T>(handoff: Arc<Handoff<T>>) -> T
where
    T: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .spawn(move || {
            let answer = zbus::block_on(handoff.wait());
            let _ = tx.send(answer);
        })
        .expect("the handoff wait thread spawns");
    rx.recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|err| panic!("the handoff wait timed out after 5 s: {err}"))
}

#[test]
fn handoff_wakes_a_waiter_parked_before_complete() {
    // The register-then-wake path: the waiter parks first and the
    // worker's `complete` must wake it. The worker sleeps a few
    // tens of milliseconds so the waiter is reliably parked when
    // it answers, without pushing the test near a second.
    let handoff = Arc::new(Handoff::new());
    let worker = Arc::clone(&handoff);
    let worker_thread = std::thread::Builder::new()
        .spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            worker.complete("late".to_string());
        })
        .expect("the handoff test worker spawns");
    let got = wait_handoff(Arc::clone(&handoff));
    worker_thread.join().expect("the handoff test worker joins");
    assert_eq!(
        got,
        "late".to_string(),
        "a parked waiter wakes with the worker's answer"
    );
}

#[test]
fn handoff_catch_unwind_answers_a_worker_that_unwound() {
    // Pins `Helper1::execute`'s containment where it holds (dev
    // and test unwind; release aborts — see `Handoff::complete`):
    // a worker that panics still answers the waiter with the
    // disconnect sentence instead of parking it forever.
    assert_eq!(
        super::WORKER_NO_ANSWER_MESSAGE,
        "the helper thread ended without an answer",
        "the fallback sentence stays byte-identical"
    );
    let handoff = Arc::new(Handoff::<zbus::fdo::Result<String>>::new());
    let worker = Arc::clone(&handoff);
    let worker_thread = std::thread::Builder::new()
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || -> Result<String, ServiceError> {
                    panic!("a worker bug in a test");
                },
            ));
            worker.complete(super::worker_answer(outcome));
        })
        .expect("the handoff test worker spawns");
    let got = wait_handoff(Arc::clone(&handoff));
    worker_thread.join().expect("the handoff test worker joins");
    assert!(
        matches!(&got, Err(zbus::fdo::Error::Failed(message)) if message == super::WORKER_NO_ANSWER_MESSAGE),
        "the unwind fallback answers with the disconnect sentence: {got:?}"
    );
}

// -- the compile-time contract -----------------------------------------

/// The bus half (5b) shares a `Registry` across async handlers
/// and raises a `ServiceError` into a `zbus` error; both must be
/// `Send + Sync`-grade so the wiring cannot break silently.
#[test]
fn registry_and_service_error_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Registry>();
    assert_send_sync::<ServiceError>();
}
