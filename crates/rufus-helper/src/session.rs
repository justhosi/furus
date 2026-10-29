//! Session directories and the single-session lock (S06).
//!
//! One helper run owns one artefact tree under [`SESSION_ROOT`]
//! (`/run/rufus-linux` on a real box):
//!
//! ```text
//! /run/rufus-linux/          root (main passes SESSION_ROOT here)
//! ├── .lock                  single-session lock; ASCII decimal pid + \n
//! └── <32-hex-id>/           one session, mode 0700
//!     ├── pid                this run's pid, ASCII decimal + \n
//!     └── plan.json          the canonical plan bytes this run executes
//! ```
//!
//! The lock protocol in one paragraph, because it is the contract that
//! keeps two helpers from ever driving the box at once (PLAN §6 "one
//! session at a time"): root/`.lock` is created with `create_new` and
//! stores *the locking run's own pid* — chosen over a pid in the
//! session directory because the lock may already be the only on-disk
//! trace of a run that died before it got a session id. A second helper
//! meeting an existing lock reads the pid: `/proc/<pid>` present means
//! another session is genuinely running (fail with code `"busy"`);
//! absent means the lock is a crash leftover — remove it once and
//! retry. A lock whose pid cannot be parsed is treated as stale for the
//! same reason: the helper is the only writer of this file, so an
//! unparseable one can only come from a crash mid-write, and wedging
//! every future run behind it would be worse than racing a dying one
//! (the retry loses at most one removal).
//!
//! [`sweep`] runs before every claim and clears the crash leftovers
//! this implies: session directories whose `pid` names a dead process,
//! and a stale `.lock`. It never follows symlinks (`symlink_metadata`
//! throughout), never removes anything that is not a directory directly
//! under `root`, and ignores errors that merely mean "already gone" —
//! two helpers sweeping concurrently is a normal race, not an incident.

use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

use rufus_core::error::CoreError;
use rufus_core::text::device_text;
use rufus_proto::Plan;

/// The default session root a real helper uses. [`Session::create`]
/// deliberately takes the root as a parameter so the unit tests can
/// point it at a scratch `tempfile` directory instead.
pub const SESSION_ROOT: &str = "/run/rufus-linux";

/// Bytes of session randomness: 16 drawn → 32 hex characters.
const ID_BYTES: usize = 16;
/// Name of the single-session lock inside `root` (dot-prefixed, so a
/// directory listing of the session root shows only sessions).
const LOCK_NAME: &str = ".lock";
/// Name of the plan copy inside a session directory.
const PLAN_FILENAME: &str = "plan.json";
/// Name of the pid record inside a session directory.
const PID_FILENAME: &str = "pid";
/// The entropy source for session ids. Never a predictable fallback:
/// an open or short-read failure is a hard error, never a made-up id.
const RANDOM_SOURCE: &str = "/dev/urandom";

/// A session id: 32 lowercase hex characters from 16 fresh random
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId {
    hex: String,
}

impl SessionId {
    /// The hex form: the directory name and every event's `session`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.hex
    }

    /// Consume the id into the opaque hex string.
    fn into_inner(self) -> String {
        self.hex
    }

    /// Draw 16 random bytes and hex-encode them (lowercase).
    ///
    /// This fails hard — never falls back, never truncates, never
    /// yields a "best effort" id — when the entropy source cannot be
    /// opened or delivers fewer bytes than requested: a predictable
    /// session id would let a second helper mistake someone else's
    /// session directory for its own.
    fn generate() -> Result<Self, SessionError> {
        let mut bytes = [0u8; ID_BYTES];
        fs::File::open(RANDOM_SOURCE)
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|source| SessionError::random(&source))?;
        // String's fmt::Write is infallible; its Result is a
        // trait-bound artefact, hence the discard.
        let mut hex = String::with_capacity(ID_BYTES * 2);
        for &byte in &bytes {
            use std::fmt::Write as _;
            let _ = write!(&mut hex, "{byte:02x}");
        }
        Ok(Self { hex })
    }
}

/// Errors of the session half, shaped like
/// [`Reject`](crate::validate::Reject) (code plus ASCII message)
/// because `CoreError` carries no machine-readable code. The codes are
/// stable snake_case strings a front end keys off: `"busy"` (another
/// live session holds the lock), `"random"` (`/dev/urandom` failed —
/// session ids are never guessed) and `"io"` (everything
/// filesystem-side: root, session or lock creation, pid/plan writes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionError {
    /// Machine-readable class, e.g. `"busy"`.
    pub code: String,
    /// ASCII explanation for the human half (sanitised on the way in).
    pub message: String,
}

impl SessionError {
    fn io(path: &Path, what: &str, source: io::Error) -> Self {
        Self {
            code: "io".to_string(),
            message: device_text(&format!("cannot {what} {}: {source}", path.display())),
        }
    }

    fn random(source: &io::Error) -> Self {
        Self {
            code: "random".to_string(),
            message: device_text(&format!(
                "cannot read the session id from {RANDOM_SOURCE}: {source}"
            )),
        }
    }

    /// The single-session lock is held — by a live process (its pid is
    /// named in the message when it could be read) or by a claim whose
    /// owner could not be read even after one clean retry.
    fn busy(pid: Option<u32>) -> Self {
        let tail = match pid {
            Some(pid) => format!("pid {pid}"),
            None => "its owner cannot be read".to_string(),
        };
        Self {
            code: "busy".to_string(),
            message: format!("another session is running ({tail})"),
        }
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SessionError {}

/// Bridge into [`CoreError`] for callers that only speak rufus-core
/// errors; the session wording survives there (`CoreError` has no code
/// slot, so under this bridge the class lives in the message only).
impl From<SessionError> for CoreError {
    fn from(err: SessionError) -> Self {
        CoreError::invalid(err.message)
    }
}

/// One live session: id, directory and lock file, removed on drop.
#[derive(Debug)]
pub struct Session {
    id: String,
    /// The two paths [`Drop`] cleans up, stored as built (never
    /// re-derived at drop time) so buggy re-derivation can never widen
    /// the cleanup to the root.
    dir: PathBuf,
    lock_path: PathBuf,
}

impl Session {
    /// Claim the single-session lock and prepare the session directory
    /// for `plan`.
    ///
    /// Fail-closed properties (PLAN §2): the session id comes from
    /// fresh entropy or the run aborts; the directory mode is 0700
    /// regardless of the umask; the plan copy is the canonical JSON the
    /// confirm hash covers (so an executor, S17+, can prove it runs the
    /// validated bytes); and any failure after the lock was claimed
    /// releases the lock again, so an EACCES can never wedge the box.
    pub fn create(root: &Path, plan: &Plan) -> Result<Session, SessionError> {
        // Fresh randomness first: a run without a real id aborts before
        // it touches any filesystem state.
        let id = SessionId::generate()?;
        fs::create_dir_all(root).map_err(|source| SessionError::io(root, "create", source))?;
        // Dead-run leftovers go away before the lock is claimed.
        sweep(root);

        let lock_path = root.join(LOCK_NAME);
        claim_lock(&lock_path).into_error()?;

        let dir = root.join(id.as_str());
        if let Err(err) = prepare_dir(&dir, plan) {
            // Now the lock (and any partial directory) is ours alone,
            // so releasing them cannot race a live run.
            let _ = fs::remove_dir_all(&dir);
            let _ = fs::remove_file(&lock_path);
            return Err(err);
        }

        Ok(Session {
            id: id.into_inner(),
            dir,
            lock_path,
        })
    }

    /// The session id (echoed as `session` in every emitted event).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The session directory (`root/<id>`, mode 0700).
    #[allow(dead_code)] // consumers: unit tests now, the executor proof path in S17
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where the canonical plan copy lives, for executors (S17+) that
    /// want to prove they run the validated bytes.
    #[allow(dead_code)] // consumed by the writing executor in S17; tests pin it meanwhile
    #[must_use]
    pub fn plan_path(&self) -> PathBuf {
        self.dir.join(PLAN_FILENAME)
    }
}

impl Drop for Session {
    /// Remove the session directory and the lock file, best effort.
    ///
    /// Every error is ignored — cleanup runs on the way out of failed
    /// runs and must never mask an original error with a panic. Only
    /// the two paths stored at creation are touched; the root itself is
    /// never removed.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
        let _ = fs::remove_file(&self.lock_path);
    }
}

/// Outcome of a lock claim: `Ok` for our claim, a genuine lock holder
/// (its pid when readable) or a filesystem failure.
enum ClaimFailure {
    Ok,
    Busy(Option<u32>),
    Broken(SessionError),
}

impl ClaimFailure {
    fn into_error(self) -> Result<(), SessionError> {
        match self {
            Self::Ok => Ok(()),
            Self::Busy(pid) => Err(SessionError::busy(pid)),
            Self::Broken(err) => Err(err),
        }
    }

    fn broken(lock: &Path, source: io::Error) -> Self {
        Self::Broken(SessionError::io(lock, "create the session lock", source))
    }
}

/// Take the lock for this run: create `lock` exclusively and store our
/// pid in it (see the module docs for the protocol). At most one
/// stale-retry happens behind an existing lock.
fn claim_lock(lock: &Path) -> ClaimFailure {
    match lock_write_new(lock) {
        Ok(mut file) => store_claim(&mut file, lock),
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            // The lock exists: busy unless its holder is provably dead
            // (or the file proves nothing), in which case it is stale.
            if let Some(pid) = read_pid_text(lock)
                && pid_alive(pid)
            {
                return ClaimFailure::Busy(Some(pid));
            }
            let _ = fs::remove_file(lock);
            // Retry exactly once; a claim that sneaks in between the
            // removal and the retry is exactly the busy condition the
            // protocol exists for.
            match lock_write_new(lock) {
                Ok(mut file) => store_claim(&mut file, lock),
                Err(_reclaimed_ahead_of_us) => ClaimFailure::Busy(read_pid_text(lock)),
            }
        }
        Err(source) => ClaimFailure::broken(lock, source),
    }
}

/// Write the pid claim into a freshly created lock file. A write
/// failure releases the claim again — an ownerless lock would wedged
/// every later run behind a pid that may not even exist.
fn store_claim(file: &mut fs::File, lock: &Path) -> ClaimFailure {
    let pid_text = format!("{}\n", std::process::id());
    if let Err(source) = file.write_all(pid_text.as_bytes()) {
        let _ = fs::remove_file(lock);
        return ClaimFailure::broken(lock, source);
    }
    // The pid must be on disk before it can be honest about ownership.
    let _ = file.flush();
    ClaimFailure::Ok
}

/// Create the lock file exclusively (fresh write handle).
fn lock_write_new(lock: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lock)
}

/// Build the session directory: the box, its mode, the pid record and
/// the canonical plan copy. Everything it does is per-session state
/// under `dir`; on failure `create` removes the partial directory.
fn prepare_dir(dir: &Path, plan: &Plan) -> Result<(), SessionError> {
    fs::create_dir(dir)
        .map_err(|source| SessionError::io(dir, "create the session directory", source))?;
    // The umask must never loosen the session directory.
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|source| SessionError::io(dir, "set the 0700 mode on", source))?;
    fs::write(dir.join(PID_FILENAME), format!("{}\n", std::process::id()))
        .map_err(|source| SessionError::io(dir, "record the run's pid in", source))?;
    // Canonical compact JSON, exactly what `Plan::confirm` hashes.
    let bytes = serde_json::to_vec(plan).map_err(|source| SessionError {
        code: "io".to_string(),
        message: device_text(&format!("cannot serialise the session plan: {source}")),
    })?;
    fs::write(dir.join(PLAN_FILENAME), &bytes)
        .map_err(|source| SessionError::io(dir, "copy the plan into", source))?;
    Ok(())
}

/// Best-effort cleanup of dead-run leftovers: a stale `.lock` and every
/// session directory whose `pid` names a dead process. Never follows
/// symlinks, never touches anything that is not a directory directly
/// under `root`, and ignores "already gone" errors (see the module
/// docs).
pub fn sweep(root: &Path) {
    clean_stale_lock(&root.join(LOCK_NAME));
    let Ok(entries) = fs::read_dir(root) else {
        return; // nothing to list (the root is yet to be created et al)
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue; // not an id we minted (32 hex); leave it alone
        };
        if name == LOCK_NAME {
            continue;
        }
        let path = entry.path();
        // lstat: a symlink (even one pointing at a directory) is never
        // a session of ours — no traversal, no removal through it.
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        // An unreadable or missing pid proves nothing (fail closed):
        // leave the directory for a run that still exists.
        let Some(pid) = read_pid_text(&path.join(PID_FILENAME)) else {
            continue;
        };
        if pid_alive(pid) {
            continue;
        }
        let _ = fs::remove_dir_all(&path);
    }
}

/// `true` while `/proc/<pid>` exists — the kernel's own answer to "is
/// this holder still running".
fn pid_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

/// The pid a lock or session `pid` file states, when it states one.
fn read_pid_text(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Remove a lock whose holder is provably dead (or whose content
/// proves nothing — see the module docs). A symlinked or otherwise
/// non-regular lock is never touched.
fn clean_stale_lock(lock: &Path) {
    let Ok(meta) = fs::symlink_metadata(lock) else {
        return; // no lock, nothing to clean
    };
    if !meta.is_file() {
        return; // a symlink (or socket/fifo plant) is never our lock
    }
    if let Some(pid) = read_pid_text(lock)
        && pid_alive(pid)
    {
        return; // a live run still owns the lock
    }
    // Dead holder, or content that cannot name one: stale.
    let _ = fs::remove_file(lock);
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::process;

    use rufus_proto::DeviceRef;
    use rufus_proto::Filesystem;
    use rufus_proto::ImageKind;
    use rufus_proto::ImageRef;
    use rufus_proto::Options;
    use rufus_proto::Plan;
    use rufus_proto::Scheme;
    use rufus_proto::Step;
    use rufus_proto::Target;

    use super::SESSION_ROOT;
    use super::Session;
    use super::SessionId;
    use super::sweep;

    // The pin: the default root is the documented one.
    #[test]
    fn session_root_const_matches_the_documented_path() {
        assert_eq!(SESSION_ROOT, "/run/rufus-linux");
    }

    /// A minimal, schema-valid plan for the session half (the
    /// validation rules live in `validate`'s tests; here the plan is
    /// opaque cargo the session copies around).
    fn sample_plan() -> Plan {
        Plan {
            version: rufus_proto::PLAN_VERSION,
            created_by: "rufus-helper tests".to_string(),
            device: DeviceRef {
                path: "/dev/sdz".to_string(),
                block_device: true,
                size_bytes: Some(8),
                serial: None,
                model: None,
                sysfs: None,
            },
            image: ImageRef {
                path: "x.iso".to_string(),
                size_bytes: 4,
                sha256: "0".repeat(64),
                kind: ImageKind::Raw,
            },
            options: Options {
                scheme: Scheme::Mbr,
                target: Target::Uefi,
                filesystem: Filesystem::Fat32,
                label: None,
                cluster_bytes: None,
                quick_format: false,
                bad_blocks: false,
                verify: false,
                persistence: false,
                show_all: false,
                confirmed_serial: None,
            },
            steps: vec![Step::Finalize],
            confirm: String::new(),
        }
    }

    // -- SessionId -------------------------------------------------------

    #[test]
    fn session_id_is_fresh_lowercase_hex() {
        let first = SessionId::generate().expect("entropy source readable");
        assert_eq!(first.as_str().len(), 32, "16 bytes → 32 hex chars");
        assert!(
            first
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "lowercase hex only: {}",
            first.as_str()
        );
        let second = SessionId::generate().expect("entropy again");
        assert_ne!(
            first.as_str(),
            second.as_str(),
            "two draws must never collide"
        );
    }

    // -- Session::create -------------------------------------------------

    #[test]
    fn create_builds_a_0700_dir_with_pid_and_canonical_plan_copy() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let root = scratch.path();
        let plan = sample_plan();

        let session = Session::create(root, &plan).expect("a fresh root claims the lock at once");

        assert_eq!(session.id().len(), 32, "the id rides on the session");
        let meta = fs::symlink_metadata(session.dir()).expect("session dir exists");
        assert!(
            meta.is_dir(),
            "the session artefact is a real directory, not a link"
        );
        assert_eq!(
            meta.mode() & 0o777,
            0o700,
            "0700 no matter what the umask says"
        );
        assert_eq!(
            fs::read_to_string(session.dir().join("pid")).expect("pid file"),
            format!("{}\n", process::id()),
            "the pid record names this run"
        );
        let plan_bytes = fs::read(session.plan_path()).expect("plan copy");
        assert_eq!(
            plan_bytes,
            serde_json::to_vec(&plan).expect("canonical serialisation"),
            "plan.json holds the canonical compact bytes"
        );
    }

    #[test]
    fn second_create_while_the_first_is_alive_is_busy() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let root = scratch.path();
        let plan = sample_plan();
        let first = Session::create(root, &plan).expect("first session claims");

        let err = Session::create(root, &plan).expect_err("the lock is held by the first run");
        assert_eq!(err.code, "busy");
        assert!(
            err.message.contains("another session is running"),
            "the message names the condition: {}",
            err.message
        );
        assert!(
            err.message.contains(&process::id().to_string()),
            "the message names the holder pid: {err}"
        );

        // The refused run left no session directory behind.
        let lock_name = std::ffi::OsString::from(".lock");
        let dirs: Vec<std::path::PathBuf> = fs::read_dir(root)
            .expect("root lists")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name() != lock_name)
            .map(|entry| entry.path())
            .collect();
        assert_eq!(dirs, vec![first.dir().to_path_buf()], "one session only");
    }

    #[test]
    fn drop_removes_the_session_dir_and_the_lock_but_never_the_root() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let root = scratch.path();
        let session = Session::create(root, &sample_plan()).expect("fresh session");
        let dir_path = session.dir().to_path_buf();
        assert!(dir_path.exists());
        assert!(root.join(".lock").exists());

        drop(session); // explicit: this is the contract under test
        assert!(!dir_path.exists(), "the session directory is gone");
        assert!(!root.join(".lock").exists(), "the lock is gone");
        assert!(root.exists(), "the root itself is never removed");
    }

    // -- sweep ------------------------------------------------------------

    /// A dead pid that cannot exist on any Linux box: the kernel's pid
    /// space is at most 2^22, so 4294967295 always means "nobody".
    const DEAD_PID: &str = "4294967295\n";

    #[test]
    fn sweep_removes_dead_pid_sessions_and_stale_locks() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let root = scratch.path();

        // A crashed run: session directory with a dead pid.
        let dead = root.join("e5ca1d5be857dd60f21a5bf3e3a2bf10");
        fs::create_dir_all(&dead).expect("seed dead session");
        fs::write(dead.join("pid"), DEAD_PID).expect("seed dead pid");

        // A live run: same shape, our own (very much alive) pid.
        let live = root.join("0123456789abcdef0123456789abcdef");
        fs::create_dir_all(&live).expect("seed live session");
        fs::write(live.join("pid"), format!("{}\n", process::id())).expect("seed live pid");

        // A stale lock (dead pid) and junk that must survive: a regular
        // file (dead pid inside) and a nested dead-pid dir behind a
        // symlink (symlinks are skipped; nothing nested is "directly
        // under root").
        fs::write(root.join(".lock"), DEAD_PID).expect("seed stale lock");
        fs::write(root.join("stranger.txt"), DEAD_PID).expect("seed junk file");
        let nested = root.join("nested");
        fs::create_dir_all(nested.join("deadchild")).expect("seed nested");
        fs::write(nested.join("deadchild").join("pid"), DEAD_PID).expect("seed nested pid");
        std::os::unix::fs::symlink(&nested, root.join("linked")).expect("seed symlinked dir");

        sweep(root);

        assert!(!dead.exists(), "a dead-pid session directory goes away");
        assert!(live.exists(), "a live-pid session directory stays");
        assert!(!root.join(".lock").exists(), "a stale lock goes away");
        assert!(
            root.join("stranger.txt").exists(),
            "non-directory entries are never removed"
        );
        assert!(
            root.join("linked").exists() && nested.join("deadchild").exists(),
            "symlinks are never followed or removed"
        );
        assert!(
            !fs::symlink_metadata(root.join("linked"))
                .expect("the link remains")
                .file_type()
                .is_dir(),
            "the link itself stays a link (lstat, not stat)"
        );
    }

    /// A pid-less directory proves nothing (fail closed), so `sweep`
    /// leaves it: only provably dead state is ever removed.
    #[test]
    fn sweep_leaves_directories_that_prove_nothing() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let root = scratch.path();
        let orphan = root.join("fedcba9876543210fedcba9876543210");
        fs::create_dir_all(&orphan).expect("seed pid-less session");

        sweep(root);
        assert!(
            orphan.exists(),
            "no pid file means no proof of death: never removed"
        );
    }
}
