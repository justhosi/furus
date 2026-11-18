//! Headless device discovery, watcher worker, and selection-stability state.
//!
//! The live system-device path is confined to [`discover`] and
//! [`start_live_watcher`]. Worker inputs and publication are injected so
//! tests exercise identical sequence/epoch handling without hardware or Slint.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rufus_core::error::Result as CoreResult;
use rufus_linux::sysfs::{self, Filter, SysfsRoot};
use rufus_linux::{Device, DeviceWatcher};

/// Bound every watcher wait so shutdown can promptly join the worker.
const WATCH_WAIT: Duration = Duration::from_millis(100);

/// Warning shown whenever fixed disks are included in the candidate list.
pub const INTERNAL_DISK_WARNING: &str =
    "WARNING: Show all exposes internal disks. Selecting the wrong device can destroy its data.";

/// A discovered, filtered candidate list and any associated safety warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    pub devices: Vec<Device>,
    pub warning: Option<String>,
}

/// Apply the real Linux candidate filter to an already-enumerated list.
///
/// Kept separate from sysfs enumeration so this policy path is directly
/// exercised by headless tests.
#[must_use]
pub fn discover_candidates(enumerated: Vec<Device>, show_all: bool) -> Discovery {
    Discovery {
        devices: sysfs::filter(enumerated, Filter { show_all }),
        warning: show_all.then(|| INTERNAL_DISK_WARNING.to_string()),
    }
}

/// Enumerate the configured sysfs tree and apply the candidate filter.
pub fn discover(root: &SysfsRoot, show_all: bool) -> CoreResult<Discovery> {
    Ok(discover_candidates(sysfs::enumerate(root)?, show_all))
}

/// One watcher publication, tagged with the selection epoch and source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceUpdate {
    pub epoch: u64,
    pub sequence: u64,
    pub devices: Vec<Device>,
    pub warning: Option<String>,
    pub error: Option<String>,
}

/// Reducer for hotplug snapshots and the currently selected stable identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceListState {
    devices: Vec<Device>,
    selected_identity: Option<String>,
    epoch: u64,
    last_sequence: u64,
    warning: Option<String>,
    error: Option<String>,
}

impl DeviceListState {
    /// Start from an initial discovery snapshot.
    #[must_use]
    pub fn new(devices: Vec<Device>, warning: Option<String>) -> Self {
        Self {
            devices,
            selected_identity: None,
            epoch: 0,
            last_sequence: 0,
            warning,
            error: None,
        }
    }

    /// Initialize the auto-selected device without advancing the user epoch.
    pub fn initialize_selection(&mut self, identity: Option<String>) {
        self.selected_identity = identity.filter(|identity| {
            self.devices
                .iter()
                .any(|device| device.identity() == *identity)
        });
    }

    /// Record a user choice and advance the epoch used to reject in-flight work.
    pub fn user_selected(&mut self, identity: Option<String>) -> u64 {
        self.epoch = self.epoch.saturating_add(1);
        self.selected_identity = identity.filter(|identity| {
            self.devices
                .iter()
                .any(|device| device.identity() == *identity)
        });
        self.epoch
    }

    /// Apply an ordered snapshot unless a newer user selection superseded it.
    /// Returns `true` only when the snapshot was accepted.
    pub fn apply(&mut self, update: DeviceUpdate) -> bool {
        if update.epoch != self.epoch || update.sequence <= self.last_sequence {
            return false;
        }
        self.last_sequence = update.sequence;
        self.devices = update.devices;
        self.warning = update.warning;
        self.error = update.error;
        if self.selected_identity.as_ref().is_some_and(|selected| {
            !self
                .devices
                .iter()
                .any(|device| device.identity() == *selected)
        }) {
            self.selected_identity = None;
        }
        true
    }

    #[must_use]
    pub fn devices(&self) -> &[Device] {
        &self.devices
    }

    #[must_use]
    pub fn selected_identity(&self) -> Option<&str> {
        self.selected_identity.as_deref()
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub fn warning(&self) -> Option<&str> {
        self.warning.as_deref()
    }

    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

/// Joinable watcher worker; dropping it also requests stop and joins.
pub struct DeviceWorker {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl DeviceWorker {
    /// Request shutdown and synchronously join the worker thread.
    pub fn shutdown(mut self) -> thread::Result<()> {
        self.stop.store(true, Ordering::Release);
        self.thread.take().expect("worker thread is present").join()
    }
}

impl Drop for DeviceWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Start the worker around an injected bounded snapshot source and publisher.
///
/// `source` must respect its supplied timeout. A `false` publisher result or
/// a source error ends the worker; closed channels are ordinary shutdown.
pub fn spawn_worker<S, E, P>(
    epoch: Arc<AtomicU64>,
    warning: Option<String>,
    initial_devices: Vec<Device>,
    mut source: S,
    mut publish: P,
) -> DeviceWorker
where
    S: FnMut(Duration) -> Result<Option<Vec<Device>>, E> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
    P: FnMut(DeviceUpdate) -> bool + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let thread = thread::spawn(move || {
        let mut sequence = 1_u64;
        let mut devices = initial_devices;
        if !publish(DeviceUpdate {
            epoch: epoch.load(Ordering::Acquire),
            sequence,
            devices: devices.clone(),
            warning: warning.clone(),
            error: None,
        }) {
            return;
        }
        while !worker_stop.load(Ordering::Acquire) {
            match source(WATCH_WAIT) {
                Ok(Some(fresh)) => {
                    sequence = sequence.saturating_add(1);
                    devices = fresh;
                    let update = DeviceUpdate {
                        epoch: epoch.load(Ordering::Acquire),
                        sequence,
                        devices: devices.clone(),
                        warning: warning.clone(),
                        error: None,
                    };
                    if !publish(update) {
                        break;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    sequence = sequence.saturating_add(1);
                    let update = DeviceUpdate {
                        epoch: epoch.load(Ordering::Acquire),
                        sequence,
                        devices,
                        warning,
                        error: Some(error.to_string()),
                    };
                    let _ = publish(update);
                    break;
                }
            }
        }
    });
    DeviceWorker {
        stop,
        thread: Some(thread),
    }
}

/// Build a live `/sys` watcher and return its initial snapshot plus worker.
pub fn start_live_watcher<P>(
    show_all: bool,
    epoch: Arc<AtomicU64>,
    publish: P,
) -> CoreResult<(Discovery, DeviceWorker)>
where
    P: FnMut(DeviceUpdate) -> bool + Send + 'static,
{
    let root = SysfsRoot::new("/sys");
    let filter = Filter { show_all };
    let mut watcher = DeviceWatcher::new(root, filter)?;
    let discovery = Discovery {
        devices: watcher.snapshot().to_vec(),
        warning: show_all.then(|| INTERNAL_DISK_WARNING.to_string()),
    };
    let initial_devices = discovery.devices.clone();
    let warning = discovery.warning.clone();
    let worker = spawn_worker(
        epoch,
        warning,
        initial_devices,
        move |timeout| watcher.wait(timeout),
        publish,
    );
    Ok((discovery, worker))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use rufus_linux::{Device, Partition, Transport};

    use super::{
        DeviceListState, DeviceUpdate, INTERNAL_DISK_WARNING, discover_candidates, spawn_worker,
    };

    fn device(name: &str) -> Device {
        Device {
            sysfs: format!("fixture/class/block/{name}"),
            name: name.to_string(),
            dev_path: format!("/dev/{name}"),
            size_bytes: 8 * 1024 * 1024,
            sector_size: 512,
            physical_sector_size: 512,
            removable: true,
            read_only: false,
            usb: true,
            vendor: Some("Test".to_string()),
            model: Some(format!("{name} test device")),
            serial: Some(format!("serial-{name}")),
            transport: Transport::Usb,
            partition_table: None,
            vid_pid: Some("1234:5678".to_string()),
            port_path: Some(format!("usb-{name}")),
            partitions: vec![Partition {
                name: format!("{name}1"),
                number: Some(1),
                size_bytes: 4096,
                fstype: Some("vfat".to_string()),
            }],
        }
    }

    fn update(epoch: u64, sequence: u64, devices: Vec<Device>) -> DeviceUpdate {
        DeviceUpdate {
            epoch,
            sequence,
            devices,
            warning: None,
            error: None,
        }
    }

    #[test]
    fn initial_list_is_available_and_selection_can_be_initialized() {
        let a = device("sda");
        let mut state = DeviceListState::new(vec![a.clone()], None);
        state.initialize_selection(Some(a.identity()));

        assert_eq!(state.devices(), &[a]);
        assert_eq!(
            state.selected_identity(),
            Some("serial=serial-sda|vidpid=1234:5678|path=usb-sda")
        );
        assert_eq!(state.epoch(), 0);
    }

    #[test]
    fn added_device_is_published_into_the_current_list() {
        let a = device("sda");
        let b = device("sdb");
        let mut state = DeviceListState::new(vec![a.clone()], None);

        assert!(state.apply(update(0, 1, vec![a.clone(), b.clone()])));
        assert_eq!(state.devices(), &[a, b]);
    }

    #[test]
    fn removing_the_selected_device_clears_the_selection() {
        let a = device("sda");
        let b = device("sdb");
        let mut state = DeviceListState::new(vec![a.clone(), b.clone()], None);
        state.initialize_selection(Some(a.identity()));

        assert!(state.apply(update(0, 1, vec![b.clone()])));
        assert_eq!(state.devices(), &[b]);
        assert_eq!(state.selected_identity(), None);
    }

    #[test]
    fn unrelated_hotplug_preserves_the_selected_device() {
        let a = device("sda");
        let b = device("sdb");
        let c = device("sdc");
        let mut state = DeviceListState::new(vec![a.clone(), b.clone()], None);
        state.initialize_selection(Some(b.identity()));

        assert!(state.apply(update(0, 1, vec![a, b.clone(), c.clone()])));
        assert_eq!(state.devices(), &[device("sda"), b.clone(), c]);
        assert_eq!(state.selected_identity(), Some(b.identity().as_str()));
    }

    #[test]
    fn stale_snapshot_cannot_clobber_a_newer_user_selection() {
        let a = device("sda");
        let b = device("sdb");
        let c = device("sdc");
        let mut state = DeviceListState::new(vec![a.clone(), b.clone(), c.clone()], None);
        state.initialize_selection(Some(a.identity()));
        let before_user_choice = update(0, 1, vec![b.clone()]);

        state.user_selected(Some(c.identity()));
        assert!(!state.apply(before_user_choice));
        assert_eq!(state.devices(), &[a, b, c.clone()]);
        assert_eq!(state.selected_identity(), Some(c.identity().as_str()));
        assert_eq!(state.epoch(), 1);
    }

    #[test]
    fn a_fresh_snapshot_after_a_user_selection_is_accepted_and_keeps_the_selection() {
        let a = device("sda");
        let b = device("sdb");
        let c = device("sdc");
        let mut state = DeviceListState::new(vec![a.clone(), b.clone()], None);
        state.initialize_selection(Some(a.identity()));
        let epoch = state.user_selected(Some(b.identity()));
        assert_eq!(epoch, 1);

        // The reject condition may only drop work that started *before* the
        // choice: a snapshot the worker completed afterwards carries the new
        // epoch and has to land, with the user's device still selected.
        assert!(state.apply(update(epoch, 5, vec![a.clone(), b.clone()])));
        assert_eq!(state.devices(), &[a.clone(), b.clone()]);
        assert_eq!(state.selected_identity(), Some(b.identity().as_str()));

        // A rejected snapshot must not latch the guard shut: the next one the
        // worker completed is still newer than anything accepted.
        assert!(!state.apply(update(epoch - 1, 6, vec![c.clone()])));
        assert!(state.apply(update(epoch, 7, vec![a.clone(), b.clone(), c.clone()])));
        assert_eq!(state.devices().len(), 3);
        assert_eq!(state.selected_identity(), Some(b.identity().as_str()));
    }

    #[test]
    fn candidate_filter_excludes_builtin_virtual_and_zero_size_devices() {
        let mut fixed_disk = device("sda");
        fixed_disk.usb = false;
        fixed_disk.removable = false;
        fixed_disk.transport = Transport::Sata;
        let mut zero_size = device("sdb");
        zero_size.size_bytes = 0;
        let mut virtual_disk = device("vdx");
        virtual_disk.transport = Transport::Virtual;
        // Kept `removable`/`usb` so the *name* rule is the only reason these
        // drop: with both flags cleared the generic removable test would hide
        // a regression of `is_builtin_name`.
        let builtin_devices = ["loop0", "ram0", "zram0", "dm-0", "md0", "sr0"].map(device);

        let mut candidates = vec![fixed_disk, zero_size, virtual_disk, device("sdc")];
        candidates.extend(builtin_devices);
        let discovery = discover_candidates(candidates, false);
        assert_eq!(
            discovery
                .devices
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            vec!["sdc"]
        );
        assert_eq!(discovery.warning, None);
    }

    #[test]
    fn show_all_discovery_surfaces_the_internal_disk_destruction_warning() {
        let mut fixed_disk = device("sda");
        fixed_disk.usb = false;
        fixed_disk.removable = false;
        fixed_disk.transport = Transport::Sata;

        let discovery = discover_candidates(vec![fixed_disk], true);
        assert_eq!(discovery.devices[0].name, "sda");
        assert_eq!(discovery.warning.as_deref(), Some(INTERNAL_DISK_WARNING));
    }

    #[test]
    fn fake_snapshot_channel_drives_the_worker_publish_seam() {
        let (source_tx, source_rx) = mpsc::channel::<Vec<Device>>();
        let (published_tx, published_rx) = mpsc::channel::<DeviceUpdate>();
        let epoch = Arc::new(AtomicU64::new(0));
        let worker = spawn_worker(
            epoch,
            None,
            Vec::new(),
            move |timeout| match source_rx.recv_timeout(timeout) {
                Ok(devices) => Ok::<_, String>(Some(devices)),
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    Err("snapshot source closed".to_string())
                }
            },
            move |update| published_tx.send(update).is_ok(),
        );

        let initial = published_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker publishes initial snapshot");
        assert_eq!(initial.epoch, 0);
        assert_eq!(initial.sequence, 1);
        assert!(initial.devices.is_empty());

        source_tx
            .send(vec![device("sda")])
            .expect("send fake snapshot");
        let received = published_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker publishes fake snapshot");
        assert_eq!(received.epoch, 0);
        assert_eq!(received.sequence, 2);
        assert_eq!(received.devices[0].name, "sda");

        worker.shutdown().expect("worker thread joins");
    }

    #[test]
    fn worker_tags_a_completed_snapshot_with_the_latest_user_epoch() {
        let (source_tx, source_rx) = mpsc::channel::<Vec<Device>>();
        let (wait_started_tx, wait_started_rx) = mpsc::channel();
        let (published_tx, published_rx) = mpsc::channel::<DeviceUpdate>();
        let epoch = Arc::new(AtomicU64::new(0));
        let worker = spawn_worker(
            Arc::clone(&epoch),
            None,
            Vec::new(),
            move |timeout| {
                wait_started_tx
                    .send(())
                    .expect("signal blocked wait started");
                match source_rx.recv_timeout(timeout) {
                    Ok(devices) => Ok(Some(devices)),
                    Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        Err("snapshot source closed".to_string())
                    }
                }
            },
            move |update| published_tx.send(update).is_ok(),
        );

        let initial = published_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker publishes its initial snapshot first");
        assert_eq!(initial.sequence, 1);
        wait_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker began waiting before selection change");
        epoch.store(1, std::sync::atomic::Ordering::Release);
        source_tx
            .send(vec![device("sda")])
            .expect("release snapshot");
        let snapshot = published_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker publishes completed snapshot");

        assert_eq!(snapshot.epoch, 1);
        assert_eq!(snapshot.sequence, 2);
        assert_eq!(epoch.load(std::sync::atomic::Ordering::Acquire), 1);
        worker.shutdown().expect("worker joins");
    }

    #[test]
    fn shutdown_joins_a_quiet_worker_promptly() {
        let worker = spawn_worker(
            Arc::new(AtomicU64::new(0)),
            None,
            Vec::new(),
            |timeout| {
                thread::sleep(timeout);
                Ok::<_, String>(None)
            },
            |_| true,
        );
        let started = Instant::now();

        worker.shutdown().expect("worker thread joins");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "shutdown was not bounded: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn publishing_to_a_closed_channel_stops_without_panicking() {
        let (source_tx, source_rx) = mpsc::channel::<Vec<Device>>();
        let (published_tx, published_rx) = mpsc::channel::<DeviceUpdate>();
        drop(published_rx);
        source_tx.send(vec![device("sda")]).expect("seed source");
        let worker = spawn_worker(
            Arc::new(AtomicU64::new(0)),
            None,
            Vec::new(),
            move |timeout| match source_rx.recv_timeout(timeout) {
                Ok(devices) => Ok::<_, String>(Some(devices)),
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    Err("snapshot source closed".to_string())
                }
            },
            move |update| published_tx.send(update).is_ok(),
        );

        worker
            .shutdown()
            .expect("closed publish channel does not panic");
    }

    #[test]
    fn later_snapshot_sequence_rejects_out_of_order_updates() {
        let a = device("sda");
        let b = device("sdb");
        let c = device("sdc");
        let mut state = DeviceListState::new(vec![a.clone()], None);

        assert!(state.apply(update(0, 2, vec![a.clone(), c.clone()])));
        assert!(!state.apply(update(0, 1, vec![a.clone(), b])));
        assert_eq!(state.devices(), &[a, c]);
    }
}
