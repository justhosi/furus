//! `rufus-gui`: the Slint front end for the Rufus-for-Linux rewrite.
//!
//! Slice S24-C C2 wires the declarative shell (`ui/main.slint`) to the
//! headless [`GuiState`] view model from `src/state.rs`. The window is
//! pure presentation plus callbacks: every value the UI shows is pushed
//! from `GuiState`, every interaction is routed back through `GuiState`
//! (whose rules live behind the S23 planner), and START only ever
//! *plans* — this crate never writes to a device.
//!
//! Startup policy (contract 0.4.3/0.4.6, S24-T4):
//! * `--version` and `--help`/`-h` exit `0` before any Slint or display
//!   initialization, so they work with `DISPLAY` and `WAYLAND_DISPLAY`
//!   both absent;
//! * the GUI refuses to run as root (pure [`startup_refusal`] of the
//!   euid): the GUI is the unprivileged half of the split, all
//!   privileged device work belongs to the separate `rufus-helper`
//!   privileged helper.
//!
//! Lint note (S24-C C2 deviation, recorded in the handoff):
//! `src/lib.rs` keeps `#![forbid(unsafe_code)]`; this binary target
//! uses `#![deny(unsafe_code)]` because Slint's generated code (via
//! `slint::include_modules!()` → `vtable-macro`'s
//! `ItemTreeVTable_static!`) hardcodes `#[allow(unsafe_code)]`, which
//! is the hard error E0453 under a crate-level `forbid`:
//!
//! ```text
//! error[E0453]: allow(unsafe_code) incompatible with previous forbid
//!     ItemTreeVTable_static ! (static VT for self :: InnerComboBox_root_1_popup_9) ;
//! ```
//!
//! `deny` keeps every hand-written line in this file free of `unsafe`
//! (no `#[allow(unsafe_code)]` appears anywhere in this crate's
//! sources); only Slint's macro expansions — which `forbid` cannot
//! legally coexist with in any crate — are exempt. The alternative is
//! moving `include_modules!` into a separate codegen-only crate.

#![deny(unsafe_code)]

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use rufus_core::planner::BootloaderOpt;
use rufus_core::report;
use rufus_gui::state::{GuiState, WindowsImageOption};
use rufus_linux::Device;
use rufus_linux::sysfs::{self, Filter, SysfsRoot};
use rufus_proto::{Filesystem, Plan, Scheme, Step, Target};
use rustix::process;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

slint::include_modules!();

/// Pure startup policy: refuse to run the GUI as root (A9).
///
/// The GUI is deliberately unprivileged; everything that needs root
/// (device writes, mkfs, bootloader installation) belongs to the
/// separate `rufus-helper` privileged helper. There is no override
/// flag. Takes the effective uid so the rule is unit-testable without
/// being root.
#[must_use]
fn startup_refusal(euid: u32) -> Option<String> {
    if euid == 0 {
        Some(
            "rufus-gui refuses to run as root (euid 0).\n\
             The GUI runs unprivileged by design; all privileged work\n\
             (device writes, mkfs, bootloader installation) belongs to\n\
             the separate rufus-helper privileged helper, which the GUI\n\
             contacts over a restricted protocol. Run rufus-gui as a\n\
             normal desktop user — there is no override flag."
                .to_string(),
        )
    } else {
        None
    }
}

fn print_version() {
    println!("rufus-gui {}", env!("CARGO_PKG_VERSION"));
}

fn print_help() {
    println!(
        "rufus-gui {} — graphical USB imaging front end (Slint)\n\
         \n\
         usage: rufus-gui [OPTION]\n\
         \n\
         options:\n\
         \x20 --version   print the version and exit\n\
         \x20 --help, -h  print this help and exit\n\
         \n\
         With no option the GUI window opens. The GUI runs unprivileged\n\
         and refuses to start as root: privileged device work belongs to\n\
         the separate rufus-helper privileged helper.",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() -> std::process::ExitCode {
    // Fast paths first: no Slint, no display, no euid check — these
    // must work headless in CI (contract 0.4.6).
    match std::env::args().nth(1).as_deref() {
        Some("--version") => {
            print_version();
            return std::process::ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            print_help();
            return std::process::ExitCode::SUCCESS;
        }
        _ => {}
    }

    if let Some(message) = startup_refusal(process::geteuid().as_raw()) {
        eprintln!("{message}");
        return std::process::ExitCode::FAILURE;
    }

    match run_gui() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rufus-gui: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Label tables: the pure display domain of the form values. The strings
// shown in every combo are provided by Rust; `ui/main.slint` never holds
// lists or defaults. All compatibility rules stay in `rufus_core::planner`
// behind `GuiState`.
// ---------------------------------------------------------------------------

const SCHEME_LABELS: &[&str] = &["MBR", "GPT"];
const TARGET_LABELS: &[&str] = &["BIOS", "UEFI", "Dual (BIOS/UEFI)"];
const FS_LABELS: &[&str] = &["FAT32", "exFAT", "NTFS", "UDF", "ext2", "ext3", "ext4"];
const IMAGE_OPTION_LABELS: &[&str] = &["Standard Windows installation", "Windows To Go"];
const BOOT_LABELS: &[&str] = &[
    "Auto",
    "Syslinux",
    "GRUB 2",
    "GRUB4DOS",
    "UEFI:NTFS",
    "FreeDOS",
    "KolibriOS",
    "MS-DOS",
    "Windows installer",
    "None (non-bootable)",
];
const CLUSTER_LABELS: &[&str] = &[
    "Default",
    "512 bytes",
    "1 KB",
    "2 KB",
    "4 KB",
    "8 KB",
    "16 KB",
    "32 KB",
    "64 KB",
];
const CLUSTER_BYTES: &[Option<u32>] = &[
    None,
    Some(512),
    Some(1024),
    Some(2048),
    Some(4096),
    Some(8192),
    Some(16384),
    Some(32768),
    Some(65536),
];
const PASSES_LABELS: &[&str] = &["1", "2", "3", "4"];

fn scheme_label(value: &Scheme) -> &'static str {
    match value {
        Scheme::Mbr => "MBR",
        Scheme::Gpt => "GPT",
    }
}

fn scheme_value(label: &str) -> Scheme {
    match label {
        "GPT" => Scheme::Gpt,
        _ => Scheme::Mbr,
    }
}

fn target_label(value: &Target) -> &'static str {
    match value {
        Target::Bios => "BIOS",
        Target::Uefi => "UEFI",
        Target::Dual => "Dual (BIOS/UEFI)",
    }
}

fn target_value(label: &str) -> Target {
    match label {
        "BIOS" => Target::Bios,
        "Dual (BIOS/UEFI)" => Target::Dual,
        _ => Target::Uefi,
    }
}

fn fs_label(value: &Filesystem) -> &'static str {
    match value {
        Filesystem::Fat32 => "FAT32",
        Filesystem::Exfat => "exFAT",
        Filesystem::Ntfs => "NTFS",
        Filesystem::Udf => "UDF",
        Filesystem::Ext2 => "ext2",
        Filesystem::Ext3 => "ext3",
        Filesystem::Ext4 => "ext4",
    }
}

fn fs_value(label: &str) -> Filesystem {
    match label {
        "exFAT" => Filesystem::Exfat,
        "NTFS" => Filesystem::Ntfs,
        "UDF" => Filesystem::Udf,
        "ext2" => Filesystem::Ext2,
        "ext3" => Filesystem::Ext3,
        "ext4" => Filesystem::Ext4,
        _ => Filesystem::Fat32,
    }
}

fn image_option_label(value: &WindowsImageOption) -> &'static str {
    match value {
        WindowsImageOption::Standard => "Standard Windows installation",
        WindowsImageOption::WindowsToGo => "Windows To Go",
    }
}

fn image_option_value(label: &str) -> WindowsImageOption {
    match label {
        "Windows To Go" => WindowsImageOption::WindowsToGo,
        _ => WindowsImageOption::Standard,
    }
}

fn boot_label(value: &BootloaderOpt) -> &'static str {
    match value {
        BootloaderOpt::Auto => "Auto",
        BootloaderOpt::Syslinux => "Syslinux",
        BootloaderOpt::Grub2 => "GRUB 2",
        BootloaderOpt::Grub4dos => "GRUB4DOS",
        BootloaderOpt::UefiNtfs => "UEFI:NTFS",
        BootloaderOpt::Freedos => "FreeDOS",
        BootloaderOpt::Kolibri => "KolibriOS",
        BootloaderOpt::MsDos => "MS-DOS",
        BootloaderOpt::Windows => "Windows installer",
        BootloaderOpt::None => "None (non-bootable)",
    }
}

fn boot_value(label: &str) -> BootloaderOpt {
    match label {
        "Syslinux" => BootloaderOpt::Syslinux,
        "GRUB 2" => BootloaderOpt::Grub2,
        "GRUB4DOS" => BootloaderOpt::Grub4dos,
        "UEFI:NTFS" => BootloaderOpt::UefiNtfs,
        "FreeDOS" => BootloaderOpt::Freedos,
        "KolibriOS" => BootloaderOpt::Kolibri,
        "MS-DOS" => BootloaderOpt::MsDos,
        "Windows installer" => BootloaderOpt::Windows,
        "None (non-bootable)" => BootloaderOpt::None,
        _ => BootloaderOpt::Auto,
    }
}

fn cluster_label(value: Option<u32>) -> &'static str {
    CLUSTER_BYTES
        .iter()
        .position(|bytes| *bytes == value)
        .map_or("Default", |index| CLUSTER_LABELS[index])
}

fn cluster_value(label: &str) -> Option<u32> {
    CLUSTER_LABELS
        .iter()
        .position(|candidate| *candidate == label)
        .and_then(|index| CLUSTER_BYTES[index])
}

fn passes_label(value: u8) -> &'static str {
    match value {
        2 => "2",
        3 => "3",
        4.. => "4",
        _ => "1",
    }
}

fn passes_value(label: &str) -> u8 {
    match label {
        "2" => 2,
        "3" => 3,
        "4" => 4,
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// Display helpers (presentation only).
// ---------------------------------------------------------------------------

fn human_size(bytes: u64) -> String {
    format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
}

fn device_label(device: &Device) -> String {
    let mut label = format!("{} ({})", device.dev_path, human_size(device.size_bytes));
    if let Some(model) = &device.model {
        label.push(' ');
        label.push_str(model);
    }
    if let Some(serial) = &device.serial {
        label.push_str(&format!(" [{serial}]"));
    }
    label
}

/// Read-only mount-state summary from `/proc/self/mounts` (display
/// facts only; reads of `/proc` are allowed for the GUI).
fn mount_summary(device: &Device) -> String {
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") else {
        return "mount state unknown".to_string();
    };
    for line in mounts.lines() {
        let Some((source, rest)) = line.split_once(' ') else {
            continue;
        };
        let same = source == device.dev_path
            || source
                .strip_prefix(&device.dev_path)
                .is_some_and(|tail| tail.chars().all(|c| c.is_ascii_digit()));
        if same {
            let target = rest.split(' ').next().unwrap_or("?");
            return format!("mounted at {target}");
        }
    }
    "not mounted".to_string()
}

fn step_name(step: &Step) -> &'static str {
    match step {
        Step::Wipe => "wipe",
        Step::Mklabel { .. } => "mklabel",
        Step::Mkpart { .. } => "mkpart",
        Step::Mkfs { .. } => "mkfs",
        Step::Write { .. } => "write",
        Step::Bootloader { .. } => "bootloader",
        Step::Finalize => "finalize",
    }
}

/// Read-only description of a planned `Plan` for the status line: the
/// plan the GUI *reports* (START never writes anything).
fn describe_plan(plan: &Plan) -> String {
    let steps: Vec<&str> = plan.steps.iter().map(step_name).collect();
    format!(
        "steps: {} (scheme {:?}, target {:?}, fs {:?})",
        steps.join(" → "),
        plan.options.scheme,
        plan.options.target,
        plan.options.filesystem
    )
}

fn model<I, S>(labels: I) -> ModelRc<SharedString>
where
    I: IntoIterator<Item = S>,
    S: Into<SharedString>,
{
    ModelRc::from(Rc::new(VecModel::from(
        labels
            .into_iter()
            .map(Into::into)
            .collect::<Vec<SharedString>>(),
    )))
}

// ---------------------------------------------------------------------------
// Session: the GUI-side wiring state. All business state lives in
// `GuiState`; the session only remembers the discovered device list and
// display-only extras (progress fraction, transient notes).
// ---------------------------------------------------------------------------

struct Session {
    state: GuiState,
    devices: Vec<Device>,
    progress: f32,
    note: Option<String>,
}

impl Session {
    fn new() -> Self {
        // One-shot discovery at startup (read-only `/sys`). The hotplug
        // watcher and selection-stability rules arrive with C3.
        let devices = sysfs::enumerate(&SysfsRoot::new("/sys"))
            .map(|found| sysfs::filter(found, Filter { show_all: false }))
            .unwrap_or_default();
        let mut session = Self {
            state: GuiState::default(),
            devices,
            progress: 0.0,
            note: None,
        };
        // Present the first discovered device as the initial selection
        // through `GuiState`, like Rufus auto-selects its first stick.
        if let Some(first) = session.devices.first().cloned() {
            let summary = mount_summary(&first);
            session.state.select_device(&first, summary);
        }
        session
    }

    fn select_device(&mut self, label: &str) {
        if let Some(device) = self
            .devices
            .iter()
            .find(|device| device_label(device) == label)
            .cloned()
        {
            let summary = mount_summary(&device);
            self.state.select_device(&device, summary);
            self.note = None;
        }
    }

    fn select_image(&mut self) {
        let Some(path) = pick_image_path() else {
            self.note = Some(
                "No file picker found (install zenity or kdialog) to select a boot image."
                    .to_string(),
            );
            return;
        };
        self.note = None;
        let is_windows = report::analyze_file(&path)
            .map(|analysis| analysis.is_windows)
            .unwrap_or(false);
        // `select_image` records the inspection outcome (including the
        // named error) in `GuiState` and its status text.
        let _ = self.state.select_image(&path, is_windows);
    }

    fn start(&mut self) {
        self.note = self
            .state
            .build_plan()
            .ok()
            .map(|plan| format!("Planned: {}", describe_plan(&plan)));
    }
}

/// Ask a desktop file picker for the boot image. Pure std process
/// spawning — no extra crates (the dependency budget is closed). The
/// analyzer worker in C4 supersedes this seam.
fn pick_image_path() -> Option<PathBuf> {
    for (program, args) in [
        (
            "zenity",
            vec![
                "--file-selection",
                "--title=Select boot image",
                "--file-filter=Images | *.iso *.img *.dd *.vhd *.vhdx *.wim *.esd",
                "--file-filter=All files | *",
            ],
        ),
        (
            "kdialog",
            vec!["--title", "Select boot image", "--getopenfilename", "."],
        ),
    ] {
        let Ok(output) = std::process::Command::new(program).args(&args).output() else {
            continue;
        };
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Rendering: `GuiState` -> UI properties. One-way display; the only
// strings the window shows come from here.
// ---------------------------------------------------------------------------

fn render(session: &Session, ui: &MainWindow) {
    let state = &session.state;

    ui.set_device_model(model(session.devices.iter().map(device_label)));
    ui.set_device_current(SharedString::from(
        state
            .device
            .as_ref()
            .and_then(|selection| {
                session
                    .devices
                    .iter()
                    .find(|device| device.dev_path == selection.path)
            })
            .map_or_else(String::new, device_label),
    ));
    ui.set_device_info(SharedString::from(match &state.device {
        Some(selection) => format!(
            "{} — {} — {} — {} — {}",
            selection.path,
            human_size(selection.size_bytes),
            selection.model.as_deref().unwrap_or("unknown model"),
            selection.serial.as_deref().unwrap_or("no serial"),
            selection.mount_summary,
        ),
        None => "No removable device selected.".to_string(),
    }));

    ui.set_boot_model(model(BOOT_LABELS.iter().copied()));
    ui.set_boot_current(SharedString::from(boot_label(&state.bootloader)));

    ui.set_select_enabled(true);

    ui.set_image_option_model(model(IMAGE_OPTION_LABELS.iter().copied()));
    ui.set_image_option_visible(state.image_option_enabled());
    ui.set_image_option_current(SharedString::from(image_option_label(&state.image_option)));

    ui.set_scheme_model(model(SCHEME_LABELS.iter().copied()));
    ui.set_scheme_current(SharedString::from(scheme_label(&state.scheme)));
    ui.set_target_model(model(TARGET_LABELS.iter().copied()));
    ui.set_target_current(SharedString::from(target_label(&state.target)));

    ui.set_fs_model(model(FS_LABELS.iter().copied()));
    ui.set_fs_enabled(state.filesystem_enabled());
    ui.set_fs_current(SharedString::from(fs_label(&state.filesystem)));

    ui.set_cluster_model(model(CLUSTER_LABELS.iter().copied()));
    ui.set_cluster_current(SharedString::from(cluster_label(state.cluster_bytes)));

    ui.set_volume_label(SharedString::from(
        state.volume_label.clone().unwrap_or_default(),
    ));
    ui.set_extended_label_checked(state.extended_label);
    ui.set_quick_format_checked(state.quick_format);

    let bad_blocks = state.bad_blocks_passes > 0;
    ui.set_bad_blocks_checked(bad_blocks);
    ui.set_passes_model(model(PASSES_LABELS.iter().copied()));
    ui.set_passes_enabled(bad_blocks);
    ui.set_passes_current(SharedString::from(passes_label(
        state.bad_blocks_passes.max(1),
    )));

    ui.set_progress_value(session.progress);
    ui.set_status_text(SharedString::from(match &session.note {
        Some(note) => format!("{}\n{note}", state.status_text()),
        None => state.status_text().to_string(),
    }));
    ui.set_start_enabled(state.clone().build_plan().is_ok());
}

// ---------------------------------------------------------------------------
// Window construction and callback wiring.
// ---------------------------------------------------------------------------

fn run_gui() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;
    let session = Rc::new(RefCell::new(Session::new()));

    // Every callback: mutate `GuiState` through the session, then
    // re-render the whole form from `GuiState` (one-way display).
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_device_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                session.borrow_mut().select_device(&label);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_boot_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.bootloader = boot_value(&label);
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_select_clicked(move || {
            if let Some(ui) = weak.upgrade() {
                session.borrow_mut().select_image();
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_image_option_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.set_image_option(image_option_value(&label));
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_scheme_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.scheme = scheme_value(&label);
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_target_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.target = target_value(&label);
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_fs_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.filesystem = fs_value(&label);
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_cluster_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.cluster_bytes = cluster_value(&label);
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_label_edited(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.volume_label = (!label.is_empty()).then(|| label.to_string());
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_extended_label_toggled(move || {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.extended_label = ui.get_extended_label_checked();
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_quick_format_toggled(move || {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.quick_format = ui.get_quick_format_checked();
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_bad_blocks_toggled(move || {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.bad_blocks_passes = if ui.get_bad_blocks_checked() { 1 } else { 0 };
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_passes_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                if guard.state.bad_blocks_passes > 0 {
                    guard.state.bad_blocks_passes = passes_value(&label);
                }
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_start_clicked(move || {
            if let Some(ui) = weak.upgrade() {
                session.borrow_mut().start();
                render(&session.borrow(), &ui);
            }
        });
    }
    ui.on_close_clicked(|| {
        let _ = slint::quit_event_loop();
    });

    render(&session.borrow(), &ui);
    ui.run()
}

#[cfg(test)]
mod tests {
    use super::startup_refusal;

    #[test]
    fn root_is_refused_with_the_unprivileged_gui_privileged_helper_split() {
        let message = startup_refusal(0).expect("euid 0 must be refused");
        assert!(
            message.contains("unprivileged"),
            "the refusal names the unprivileged GUI half: {message}"
        );
        assert!(
            message.contains("rufus-helper") && message.contains("helper"),
            "the refusal names the privileged helper half: {message}"
        );
        assert!(
            message.contains("no override flag"),
            "the refusal must state there is no override: {message}"
        );
    }

    #[test]
    fn unprivileged_euids_start_normally() {
        for euid in [1_u32, 60_000, 65_534] {
            assert!(
                startup_refusal(euid).is_none(),
                "euid {euid} must not be refused"
            );
        }
    }
}
