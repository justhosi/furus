//! The display-independent `GuiState` view model and its planner bridge.
//!
//! Every business rule of the Furus form lives here, never in the UI
//! toolkit: which options are enabled, which defaults are selected, what
//! status text is shown, and the resulting [`furus_proto::Plan`] (or a
//! named refusal). Plan construction and every scheme/target/filesystem
//! compatibility rule go through the shared S23 planner
//! (`furus_core::planner`), and partition-layout refusals through
//! `furus_core::part::plan` — the GUI surfaces their text and never
//! re-implements the rules.

use std::fmt;
use std::path::Path;

use furus_core::image;
use furus_core::part::TableKind;
use furus_core::part::plan::{DataType, LayoutKind};
use furus_core::planner::{self, BootloaderOpt, DeviceProbe, PlanError};
use furus_core::report::ImageReport;
use furus_linux::Device;
use furus_proto::{Filesystem, ImageRef, Layout, Plan, Scheme, Step, Target};

/// The Windows-specific image handling choice shown by the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WindowsImageOption {
    /// Preserve the image's normal installation flow.
    #[default]
    Standard,
    /// Plan the portable Windows (Windows To Go) layout.
    WindowsToGo,
}

/// Display facts for the currently selected removable device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSelection {
    pub identity: String,
    pub path: String,
    pub size_bytes: u64,
    pub sector_size: u32,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub sysfs: String,
    pub mount_summary: String,
}

/// Inspected image facts plus the analyzer's Windows classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSelection {
    pub image: ImageRef,
    /// The real SHA-256 only after background hashing has completed.
    pub sha256: Option<String>,
    /// Latest background digest progress, when hashing is pending.
    pub digest_progress: Option<u8>,
    pub is_windows: bool,
    pub report: ImageReport,
}

/// A state or planner error surfaced to the GUI without panicking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuiError {
    ImageInspection(String),
    Layout(String),
    NoDevice,
    NoImage,
    Plan(PlanError),
}

impl fmt::Display for GuiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImageInspection(message) => formatter.write_str(message),
            Self::Layout(message) => formatter.write_str(message),
            Self::NoDevice => formatter.write_str("Select a removable device before planning."),
            Self::NoImage => formatter.write_str("Select a boot image before planning."),
            Self::Plan(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for GuiError {}

/// Pure, display-independent model of the Furus form and planner bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuiState {
    pub device: Option<DeviceSelection>,
    pub image: Option<BootSelection>,
    pub image_option: WindowsImageOption,
    pub scheme: Scheme,
    pub target: Target,
    pub filesystem: Filesystem,
    pub cluster_bytes: Option<u32>,
    pub volume_label: Option<String>,
    pub quick_format: bool,
    pub extended_label: bool,
    pub bad_blocks_passes: u8,
    /// Copy an ISO tree rather than writing its sectors.
    pub iso_mode: bool,
    /// Planner selector needed to express supported installer combinations.
    pub bootloader: BootloaderOpt,
    status: String,
    last_error: Option<GuiError>,
}

impl GuiState {
    /// Set the selected device's display facts.
    pub fn select_device(&mut self, device: &Device, mount_summary: impl Into<String>) {
        self.device = Some(DeviceSelection {
            identity: device.identity(),
            path: device.dev_path.clone(),
            size_bytes: device.size_bytes,
            sector_size: device.sector_size,
            model: device.model.clone(),
            serial: device.serial.clone(),
            sysfs: device.sysfs.clone(),
            mount_summary: mount_summary.into(),
        });
        self.status = format!("Selected {}", device.dev_path);
        self.last_error = None;
    }

    /// Clear the selected device when a hotplug refresh removes it.
    pub fn clear_device(&mut self) {
        self.device = None;
        self.status = "Selected device was disconnected.".to_string();
        self.last_error = None;
    }

    /// Mark a newly selected image as pending and clear the previous image
    /// so no plan can be built against stale facts while analysis runs.
    pub fn begin_image_analysis(&mut self, path: &Path) {
        self.image = None;
        self.last_error = None;
        self.image_option = WindowsImageOption::Standard;
        self.bootloader = BootloaderOpt::Auto;
        self.iso_mode = false;
        self.scheme = Scheme::Gpt;
        self.target = Target::Uefi;
        self.filesystem = Filesystem::Fat32;
        self.volume_label = None;
        self.status = format!("Analyzing image '{}'…", path.display());
    }

    /// Apply fast image facts before the background digest is available.
    pub fn apply_image_metadata(&mut self, metadata: image::ImageMetadata, report: ImageReport) {
        let is_windows = report.is_windows;
        let volume_label = report.labels.best().map(str::to_string);
        self.image = Some(BootSelection {
            image: ImageRef {
                path: metadata.path,
                size_bytes: metadata.size_bytes,
                // Empty only in the view model while `sha256` is `None`; the
                // planner is explicitly gated until a genuine digest arrives.
                sha256: String::new(),
                kind: metadata.kind,
            },
            sha256: None,
            digest_progress: Some(0),
            is_windows,
            report,
        });
        self.image_option = WindowsImageOption::Standard;
        self.bootloader = BootloaderOpt::Auto;
        self.iso_mode = false;
        self.scheme = Scheme::Gpt;
        self.target = Target::Uefi;
        self.filesystem = if is_windows {
            Filesystem::Ntfs
        } else {
            Filesystem::Fat32
        };
        let image = self.image.as_ref().expect("image was just assigned");
        self.volume_label = volume_label;
        self.status = format!("{} (computing SHA-256… 0%)", analysis_summary(image));
        self.last_error = None;
    }

    /// Update digest progress for the currently selected image.
    pub fn update_image_digest_progress(&mut self, percent: u8) {
        let Some(image) = self.image.as_mut() else {
            return;
        };
        if image.sha256.is_some() {
            return;
        }
        image.digest_progress = Some(percent);
        self.status = format!(
            "{} (computing SHA-256… {percent}%)",
            analysis_summary(image)
        );
    }

    /// Store the completed real digest and make planning available.
    pub fn apply_image_digest(&mut self, sha256: String) {
        let Some(image) = self.image.as_mut() else {
            return;
        };
        image.image.sha256.clone_from(&sha256);
        image.sha256 = Some(sha256);
        image.digest_progress = None;
        self.status = analysis_summary(image);
        self.last_error = None;
    }

    /// Apply facts produced by the synchronous inspector, which already
    /// includes a completed digest.
    pub fn apply_image_analysis(&mut self, info: image::ImageInfo, report: ImageReport) {
        self.apply_image_metadata(
            image::ImageMetadata {
                path: info.path,
                size_bytes: info.size_bytes,
                kind: info.kind,
            },
            report,
        );
        self.apply_image_digest(info.sha256);
    }

    /// Whether a digest is still being computed for the current image.
    #[must_use]
    pub fn image_digest_pending(&self) -> bool {
        self.image
            .as_ref()
            .is_some_and(|image| image.sha256.is_none())
    }

    /// Apply a named analyzer failure, leaving the selected image absent.
    pub fn fail_image_analysis(&mut self, path: &Path, message: impl fmt::Display) {
        self.image = None;
        let error = GuiError::ImageInspection(format!(
            "Could not analyze image '{}': {message}",
            path.display()
        ));
        self.status = error.to_string();
        self.last_error = Some(error);
    }

    /// Inspect a selected image synchronously. Retained for headless callers;
    /// the desktop picker uses `begin_image_analysis` and the worker instead.
    pub fn select_image(&mut self, path: &Path, is_windows: bool) -> Result<(), GuiError> {
        self.begin_image_analysis(path);
        match image::inspect(path) {
            Ok(info) => {
                let report = ImageReport {
                    is_windows,
                    ..ImageReport::default()
                };
                self.apply_image_analysis(info, report);
                Ok(())
            }
            Err(error) => {
                self.fail_image_analysis(path, &error);
                Err(self.last_error.clone().unwrap_or(GuiError::NoImage))
            }
        }
    }

    /// Whether START is actionable; the shared planner remains the single
    /// source of truth for whether current state has a valid plan.
    #[must_use]
    pub fn start_enabled(&self) -> bool {
        let mut state = self.clone();
        state.build_plan().is_ok()
    }

    /// Whether the Windows image option selector should be shown/enabled.
    #[must_use]
    pub fn image_option_enabled(&self) -> bool {
        self.image.as_ref().is_some_and(|image| image.is_windows)
    }

    /// Apply the image option; non-Windows images cannot select Windows To Go.
    pub fn set_image_option(&mut self, option: WindowsImageOption) -> bool {
        if !self.image_option_enabled() {
            return false;
        }
        self.image_option = option;
        if option == WindowsImageOption::WindowsToGo {
            self.bootloader = BootloaderOpt::Windows;
            self.filesystem = Filesystem::Ntfs;
        } else if self.bootloader == BootloaderOpt::Windows {
            self.bootloader = BootloaderOpt::Auto;
        }
        self.status = match option {
            WindowsImageOption::Standard => "Standard Windows installation selected.".to_string(),
            WindowsImageOption::WindowsToGo => "Windows To Go selected.".to_string(),
        };
        self.last_error = None;
        true
    }

    /// Whether the filesystem picker is editable for the current options.
    #[must_use]
    pub fn filesystem_enabled(&self) -> bool {
        self.image_option != WindowsImageOption::WindowsToGo || !self.image_option_enabled()
    }

    /// The most recent status or planner/inspection refusal text.
    #[must_use]
    pub fn status_text(&self) -> &str {
        &self.status
    }

    /// Build the current plan, storing a user-readable result status.
    pub fn build_plan(&mut self) -> Result<Plan, GuiError> {
        self.build_plan_with_bootloader(self.bootloader)
    }

    /// Build through the shared planner using a specific bootloader selector.
    pub fn build_plan_with_bootloader(
        &mut self,
        bootloader: BootloaderOpt,
    ) -> Result<Plan, GuiError> {
        let result = self.build_plan_inner(bootloader);
        match &result {
            Ok(_) => {
                self.status = "Plan ready.".to_string();
                self.last_error = None;
            }
            Err(error) => {
                self.status = error.to_string();
                self.last_error = Some(error.clone());
            }
        }
        result
    }

    /// Return the provisional plan or the named refusal for current state.
    pub fn plan_result(&mut self) -> Result<Plan, GuiError> {
        if let Some(error) = &self.last_error {
            return Err(error.clone());
        }
        self.build_plan()
    }

    /// The planner selector the form resolves: Windows To Go always
    /// plans through the Windows (WIM-applying) installer.
    fn effective_bootloader(&self, requested: BootloaderOpt) -> BootloaderOpt {
        if self.image_option_enabled() && self.image_option == WindowsImageOption::WindowsToGo {
            BootloaderOpt::Windows
        } else {
            requested
        }
    }

    fn build_plan_inner(&self, bootloader: BootloaderOpt) -> Result<Plan, GuiError> {
        let device = self.device.as_ref().ok_or(GuiError::NoDevice)?;
        let image = self
            .image
            .as_ref()
            .ok_or_else(|| self.last_error.clone().unwrap_or(GuiError::NoImage))?;
        let Some(sha256) = image.sha256.as_deref() else {
            return Err(GuiError::ImageInspection(
                "Image SHA-256 is still being computed.".to_string(),
            ));
        };
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(GuiError::ImageInspection(
                "Image SHA-256 is not a valid lowercase hexadecimal digest.".to_string(),
            ));
        }
        let probe = DeviceProbe {
            path: device.path.clone(),
            exists: true,
            block_device: true,
            error: None,
            facts: Some(planner::DeviceFacts {
                size_bytes: device.size_bytes,
                serial: device.serial.clone(),
                model: device.model.clone(),
                sysfs: device.sysfs.clone(),
            }),
        };
        let device_ref = planner::device_ref(&probe, false).map_err(GuiError::Plan)?;
        let options = planner::Options {
            scheme: self.scheme.clone(),
            target: self.target.clone(),
            // `planner::build` pins NTFS for `BootloaderOpt::Windows`
            // whatever is asked here; the GUI never re-implements the pin.
            filesystem: self.filesystem.clone(),
            label: self.volume_label.clone(),
            cluster_bytes: self.cluster_bytes,
            quick_format: self.quick_format,
            iso_mode: self.iso_mode,
            bootloader: self.effective_bootloader(bootloader),
            msdos_dir: None,
            bad_blocks: self.bad_blocks_passes > 0,
            verify: false,
            persistence: false,
            show_all: false,
            confirmed_serial: None,
        };
        let plan =
            planner::build(device_ref, image.image.clone(), &options).map_err(GuiError::Plan)?;
        check_layout(&plan, device)?;
        Ok(plan)
    }
}

/// Surface, at plan time, the refusals `furus_core::part::plan` raises
/// for the sealed plan's mkpart geometry — the same `request` + `plan`
/// pair `pipeline::mkpart` runs at write time (including the
/// GPT-only `windows-to-go` layout). The `CoreError` text is surfaced
/// verbatim in [`GuiError::Layout`]; the GUI never re-writes the rule.
fn check_layout(plan: &Plan, device: &DeviceSelection) -> Result<(), GuiError> {
    let Some((scheme, layout)) = plan.steps.iter().find_map(|step| match step {
        Step::Mkpart { scheme, layout } => Some((scheme, layout)),
        _ => None,
    }) else {
        return Ok(());
    };
    let request = furus_core::part::plan::request(
        layout_kind(layout),
        table_kind(scheme),
        device.sector_size,
        device.size_bytes,
        data_type(&plan.options.filesystem),
    )
    .map_err(|error| GuiError::Layout(error.to_string()))?;
    furus_core::part::plan::plan(&request).map_err(|error| GuiError::Layout(error.to_string()))?;
    Ok(())
}

impl Default for GuiState {
    fn default() -> Self {
        Self {
            device: None,
            image: None,
            image_option: WindowsImageOption::Standard,
            scheme: Scheme::Gpt,
            target: Target::Uefi,
            filesystem: Filesystem::Fat32,
            cluster_bytes: None,
            volume_label: None,
            quick_format: true,
            extended_label: false,
            bad_blocks_passes: 0,
            iso_mode: false,
            bootloader: BootloaderOpt::Auto,
            status: "Select a device and boot image.".to_string(),
            last_error: None,
        }
    }
}

/// A user-facing summary of analyzer facts; planning remains in `GuiState`
/// and the shared planner.
fn analysis_summary(image: &BootSelection) -> String {
    let report = &image.report;
    let boot_modes = match (report.has_bios, report.has_efi) {
        (true, true) => "BIOS/UEFI",
        (true, false) => "BIOS",
        (false, true) => "UEFI",
        (false, false) => "no BIOS/UEFI boot path",
    };
    let windows = if report.is_windows {
        let version = report.windows_version.as_deref().map_or_else(
            || "Windows".to_string(),
            |version| format!("Windows {version}"),
        );
        let edition = report
            .wim_images
            .first()
            .and_then(|edition| edition.display_name.as_deref().or(edition.name.as_deref()));
        match edition {
            Some(edition) => format!("{version} / {edition}"),
            None => version,
        }
    } else {
        report
            .distro
            .as_deref()
            .unwrap_or("non-Windows image")
            .to_string()
    };
    let distro = report
        .distro
        .as_deref()
        .map(|distro| format!(" — distro: {distro}"))
        .unwrap_or_default();
    format!(
        "Analyzed: {} — {windows} — {boot_modes}{distro}",
        report.kind
    )
}

/// `Scheme` to the shared layout planner's `TableKind`: the same wire
/// mapping `furus-cli` and `pipeline::mkpart` write at their boundaries.
fn table_kind(scheme: &Scheme) -> TableKind {
    match scheme {
        Scheme::Mbr => TableKind::Mbr,
        Scheme::Gpt => TableKind::Gpt,
    }
}

/// `Layout` to the shared layout planner's `LayoutKind`: the same wire
/// mapping `pipeline::steps::layout_kind_of` writes.
fn layout_kind(layout: &Layout) -> LayoutKind {
    match layout {
        Layout::Single => LayoutKind::Single,
        Layout::UefiNtfs => LayoutKind::UefiNtfs,
        Layout::WindowsToGo => LayoutKind::WindowsToGo,
        Layout::Persistence => LayoutKind::Persistence,
    }
}

/// The `data` partition type for the plan's filesystem: the same wire
/// mapping `pipeline::mkpart::data_type_of` writes.
fn data_type(filesystem: &Filesystem) -> DataType {
    match filesystem {
        Filesystem::Fat32 => DataType::Fat32,
        Filesystem::Exfat => DataType::Exfat,
        Filesystem::Ntfs => DataType::Ntfs,
        Filesystem::Ext2 | Filesystem::Ext3 | Filesystem::Ext4 => DataType::Linux,
        Filesystem::Udf => DataType::MicrosoftBasicData,
    }
}

/// Convert a discovered Linux device to the shared planner probe shape.
#[must_use]
pub fn device_probe_from_device(device: &Device) -> DeviceProbe {
    DeviceProbe {
        path: device.dev_path.clone(),
        exists: true,
        block_device: true,
        error: None,
        facts: Some(planner::DeviceFacts {
            size_bytes: device.size_bytes,
            serial: device.serial.clone(),
            model: device.model.clone(),
            sysfs: device.sysfs.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use furus_core::part::TableKind;
    use furus_core::part::plan::{self, DataType, LayoutKind};
    use furus_core::planner::{BootloaderOpt, PlanError};
    use furus_linux::{Device, Partition, Transport};
    use furus_proto::{
        BootloaderMode, Filesystem, ImageKind, Layout, Scheme, Step, Target, WriteMode,
    };

    use super::{GuiError, GuiState, WindowsImageOption, device_probe_from_device};

    static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);

    struct ImageFile(PathBuf);

    impl ImageFile {
        fn at(extension: &str) -> PathBuf {
            let serial = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            std::env::temp_dir().join(format!(
                "furus-gui-state-{}-{serial}.{extension}",
                std::process::id()
            ))
        }

        /// A sector image with no recognised container magic.
        fn raw() -> Self {
            let path = Self::at("img");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .expect("create unique raw fixture");
            std::io::Write::write_all(&mut file, &[0xA5; 4096]).expect("write raw fixture");
            Self(path)
        }

        /// A file shorter than every detection probe: `ImageKind::Unknown`.
        fn unknown() -> Self {
            let path = Self::at("img");
            fs::write(&path, []).expect("write empty fixture");
            Self(path)
        }

        /// A synthetic ISO9660 image (`CD001` at 0x8001).
        fn iso() -> Self {
            let path = Self::at("iso");
            let mut bytes = vec![0; 0x9000];
            bytes[0x8001..0x8006].copy_from_slice(b"CD001");
            fs::write(&path, bytes).expect("write ISO fixture");
            Self(path)
        }
    }

    impl Drop for ImageFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn sample_device() -> Device {
        Device {
            sysfs: "/sys/class/block/sdz".to_string(),
            name: "sdz".to_string(),
            dev_path: "/dev/sdz".to_string(),
            size_bytes: 32_010_928_128,
            sector_size: 512,
            physical_sector_size: 4096,
            removable: true,
            read_only: false,
            usb: true,
            vendor: Some("Furus".to_string()),
            model: Some("Test Stick".to_string()),
            serial: Some("ABC123".to_string()),
            transport: Transport::Usb,
            partition_table: None,
            vid_pid: Some("1234:5678".to_string()),
            port_path: Some("usb-1:2".to_string()),
            partitions: vec![Partition {
                name: "sdz1".to_string(),
                number: Some(1),
                size_bytes: 1_048_576,
                fstype: Some("vfat".to_string()),
            }],
        }
    }

    fn selected_state(image: &ImageFile, is_windows: bool) -> GuiState {
        let mut state = GuiState::default();
        state.select_device(&sample_device(), "not mounted");
        state
            .select_image(&image.0, is_windows)
            .expect("inspect test image");
        state
    }

    fn bootloader(plan: &furus_proto::Plan) -> Option<&BootloaderMode> {
        plan.steps.iter().find_map(|step| match step {
            Step::Bootloader { mode } => Some(mode),
            _ => None,
        })
    }

    fn write_mode(plan: &furus_proto::Plan) -> Option<&WriteMode> {
        plan.steps.iter().find_map(|step| match step {
            Step::Write { mode } => Some(mode),
            _ => None,
        })
    }

    fn mkfs(plan: &furus_proto::Plan) -> Option<&Filesystem> {
        plan.steps.iter().find_map(|step| match step {
            Step::Mkfs { filesystem, .. } => Some(filesystem),
            _ => None,
        })
    }

    #[test]
    fn clearing_a_hot_unplugged_device_removes_it_from_planning_state() {
        let mut state = GuiState::default();
        state.select_device(&sample_device(), "not mounted");

        state.clear_device();

        assert!(state.device.is_none());
        assert_eq!(state.status_text(), "Selected device was disconnected.");
        assert!(matches!(state.build_plan(), Err(GuiError::NoDevice)));
    }

    #[test]
    fn windows_iso_enables_the_image_option_defaults_and_builds_the_windows_plan() {
        let image = ImageFile::iso();
        let mut state = selected_state(&image, true);
        assert_eq!(
            state.image.as_ref().expect("image").image.kind,
            ImageKind::Iso
        );

        assert!(state.image_option_enabled());
        assert_eq!(state.image_option, WindowsImageOption::Standard);
        assert!(
            state.set_image_option(WindowsImageOption::WindowsToGo),
            "Windows To Go must be selectable on a Windows image"
        );
        assert_eq!(state.image_option, WindowsImageOption::WindowsToGo);
        assert!(state.set_image_option(WindowsImageOption::Standard));
        assert_eq!(state.scheme, Scheme::Gpt);
        assert_eq!(state.target, Target::Uefi);
        assert_eq!(state.filesystem, Filesystem::Ntfs);

        // The standard install flow copies the image tree and pairs the
        // installer with it.
        state.iso_mode = true;
        let plan = state.build_plan().expect("standard Windows plan");
        assert_eq!(plan.options.scheme, Scheme::Gpt);
        assert_eq!(plan.options.target, Target::Uefi);
        assert_eq!(plan.options.filesystem, Filesystem::Ntfs);
        assert_eq!(write_mode(&plan), Some(&WriteMode::Copy));
        assert!(
            bootloader(&plan).is_some(),
            "the plan carries the Windows bootloader step"
        );

        // The Windows bootloader path itself: the WIM-applying installer.
        state.set_image_option(WindowsImageOption::WindowsToGo);
        let plan = state.build_plan().expect("Windows bootloader plan");
        assert_eq!(bootloader(&plan), Some(&BootloaderMode::Windows));
    }

    #[test]
    fn windows_to_go_uses_the_windows_to_go_layout_pins_ntfs_and_refuses_mbr() {
        let image = ImageFile::iso();
        let mut state = selected_state(&image, true);
        state.set_image_option(WindowsImageOption::WindowsToGo);
        assert!(
            !state.filesystem_enabled(),
            "Windows To Go pins the filesystem"
        );

        let plan = state.build_plan().expect("Windows To Go plan");
        assert!(plan.steps.iter().any(|step| matches!(
            step,
            Step::Mkpart {
                layout: Layout::WindowsToGo,
                ..
            }
        )));
        assert_eq!(bootloader(&plan), Some(&BootloaderMode::Windows));
        assert_eq!(plan.options.filesystem, Filesystem::Ntfs);
        assert_eq!(mkfs(&plan), Some(&Filesystem::Ntfs));

        // The pin is the shared planner's, not a GUI copy: even a
        // tampered form value records NTFS (`planner::build` overrides
        // the filesystem for `BootloaderOpt::Windows`).
        state.filesystem = Filesystem::Ext4;
        let plan = state.build_plan().expect("NTFS-pinned plan");
        assert_eq!(plan.options.filesystem, Filesystem::Ntfs);
        assert_eq!(mkfs(&plan), Some(&Filesystem::Ntfs));

        // MBR is refused by `furus_core::part::plan` (the layout is
        // GPT-only) and that refusal is surfaced verbatim.
        let device = sample_device();
        let request = plan::request(
            LayoutKind::WindowsToGo,
            TableKind::Mbr,
            device.sector_size,
            device.size_bytes,
            DataType::MicrosoftBasicData,
        )
        .expect("geometry is plannable");
        let expected = plan::plan(&request)
            .expect_err("windows-to-go refuses MBR in the shared layout planner")
            .to_string();
        assert!(
            expected.contains("render this layout on gpt"),
            "shared refusal names the fix: {expected}"
        );

        state.scheme = Scheme::Mbr;
        let error = state.build_plan().expect_err("Windows To Go requires GPT");
        assert!(matches!(error, GuiError::Layout(_)), "got {error:?}");
        assert_eq!(error.to_string(), expected);
        assert_eq!(state.status_text(), expected);
        assert!(
            state.plan_result().is_err(),
            "a refused state never yields a Plan"
        );
    }

    #[test]
    fn linux_iso_hides_the_image_option_and_supports_dd_and_copy_modes() {
        let image = ImageFile::iso();
        let mut state = selected_state(&image, false);
        assert_eq!(
            state.image.as_ref().expect("image").image.kind,
            ImageKind::Iso
        );

        assert!(!state.image_option_enabled());
        assert!(
            !state.set_image_option(WindowsImageOption::WindowsToGo),
            "no selector means no Windows To Go"
        );
        assert_eq!(state.image_option, WindowsImageOption::Standard);
        assert_eq!(state.scheme, Scheme::Gpt);
        assert_eq!(state.target, Target::Uefi);
        assert_eq!(state.filesystem, Filesystem::Fat32);

        let dd_plan = state.build_plan().expect("dd plan");
        assert_eq!(write_mode(&dd_plan), Some(&WriteMode::Dd));

        state.iso_mode = true;
        let copy_plan = state.build_plan().expect("ISO/copy plan");
        assert_eq!(write_mode(&copy_plan), Some(&WriteMode::Copy));
    }

    #[test]
    fn raw_and_unknown_images_stay_selectable_and_plan_no_bootloader_install() {
        for fixture in [ImageFile::raw(), ImageFile::unknown()] {
            let mut state = selected_state(&fixture, false);
            assert!(
                matches!(
                    state.image.as_ref().expect("image").image.kind,
                    ImageKind::Raw | ImageKind::Unknown
                ),
                "raw/unknown kinds only"
            );

            state.scheme = Scheme::Mbr;
            state.filesystem = Filesystem::Ext4;
            let plan = state.build_plan().expect("raw image plan");
            assert_eq!(plan.options.scheme, Scheme::Mbr);
            assert_eq!(plan.options.filesystem, Filesystem::Ext4);
            assert_eq!(write_mode(&plan), Some(&WriteMode::Dd));
            assert_eq!(
                bootloader(&plan),
                Some(&BootloaderMode::None),
                "no bootloader install is planned for raw media"
            );
        }
    }

    #[test]
    fn unreadable_or_non_regular_images_are_named_and_never_planned() {
        let mut state = GuiState::default();
        state.select_device(&sample_device(), "not mounted");

        let missing = ImageFile::at("iso");
        let error = state
            .select_image(&missing, false)
            .expect_err("missing image must fail inspection");
        assert!(
            matches!(error, GuiError::ImageInspection(_)),
            "got {error:?}"
        );
        assert!(error.to_string().contains(&missing.display().to_string()));
        assert!(state.image.is_none(), "a refused image never enters state");
        assert!(state.plan_result().is_err(), "no Plan without an image");

        let directory = std::env::temp_dir();
        let error = state
            .select_image(&directory, false)
            .expect_err("directory is not an image file");
        assert!(
            matches!(error, GuiError::ImageInspection(_)),
            "got {error:?}"
        );
        assert!(error.to_string().contains(&directory.display().to_string()));
        assert!(state.image.is_none());

        // A regular but unreadable file. The root user can read anything,
        // so the case is only observable unprivileged.
        let locked = ImageFile::raw();
        fs::set_permissions(&locked.0, fs::Permissions::from_mode(0o000))
            .expect("drop fixture permissions");
        if fs::File::open(&locked.0).is_err() {
            let error = state
                .select_image(&locked.0, false)
                .expect_err("unreadable image must fail inspection");
            assert!(
                matches!(error, GuiError::ImageInspection(_)),
                "got {error:?}"
            );
            assert!(error.to_string().contains(&locked.0.display().to_string()));
            assert!(state.image.is_none());
        }
    }

    #[test]
    fn planner_usage_disagreements_are_surfaced_verbatim_in_the_state() {
        let image = ImageFile::raw();
        let mut state = selected_state(&image, false);

        for (bootloader_opt, filesystem, message) in [
            (
                BootloaderOpt::UefiNtfs,
                Filesystem::Fat32,
                "UEFI:NTFS needs an NTFS or exFAT data partition; choose --filesystem ntfs or exfat",
            ),
            (
                BootloaderOpt::Freedos,
                Filesystem::Ntfs,
                "FreeDOS needs a FAT32 data partition; choose --filesystem fat32",
            ),
            (
                BootloaderOpt::Kolibri,
                Filesystem::Ext4,
                "KolibriOS needs a FAT32 data partition; choose --filesystem fat32",
            ),
            (
                BootloaderOpt::MsDos,
                Filesystem::Exfat,
                "MS-DOS needs a FAT32 data partition; choose --filesystem fat32",
            ),
        ] {
            state.filesystem = filesystem;
            let error = state
                .build_plan_with_bootloader(bootloader_opt)
                .expect_err("planner must refuse the incompatible pair");
            assert!(
                matches!(error, GuiError::Plan(PlanError::Usage(_))),
                "got {error:?}"
            );
            assert_eq!(error.to_string(), message);
            assert_eq!(state.status_text(), message);
        }
    }

    #[test]
    fn discovered_device_maps_real_facts_and_missing_or_non_block_paths_are_refused() {
        let device = sample_device();
        let probe = device_probe_from_device(&device);
        assert_eq!(probe.path, "/dev/sdz");
        assert!(probe.exists);
        assert!(probe.block_device);
        let facts = probe.facts.as_ref().expect("discovery facts");
        assert_eq!(facts.size_bytes, 32_010_928_128);
        assert_eq!(facts.serial.as_deref(), Some("ABC123"));
        assert_eq!(facts.model.as_deref(), Some("Test Stick"));
        assert_eq!(facts.sysfs, "/sys/class/block/sdz");

        let reference = furus_core::planner::device_ref(&probe, false)
            .expect("planner accepts the discovered block device");
        assert!(reference.block_device);
        assert_eq!(reference.size_bytes, Some(32_010_928_128));
        assert_eq!(reference.serial.as_deref(), Some("ABC123"));
        assert_eq!(reference.model.as_deref(), Some("Test Stick"));
        assert_eq!(reference.sysfs.as_deref(), Some("/sys/class/block/sdz"));
        // The GUI mapping agrees field-for-field with the shared
        // furus-linux `Device` to `DeviceRef` mapping.
        assert_eq!(reference, furus_linux::plan_device_ref(&device));

        // The selected-device display facts carry the same fields.
        let mut state = GuiState::default();
        state.select_device(&device, "mounted at /media/stick");
        let selection = state.device.as_ref().expect("selected device");
        assert_eq!(selection.identity, device.identity());
        assert_eq!(selection.path, "/dev/sdz");
        assert_eq!(selection.size_bytes, 32_010_928_128);
        assert_eq!(selection.model.as_deref(), Some("Test Stick"));
        assert_eq!(selection.serial.as_deref(), Some("ABC123"));
        assert_eq!(selection.sysfs, "/sys/class/block/sdz");
        assert_eq!(selection.sector_size, 512);
        assert_eq!(selection.mount_summary, "mounted at /media/stick");

        let missing = furus_core::planner::DeviceProbe {
            path: "/dev/missing-furus-test".to_string(),
            exists: false,
            block_device: false,
            error: Some("No such file or directory".to_string()),
            facts: None,
        };
        assert!(matches!(
            furus_core::planner::device_ref(&missing, false),
            Err(PlanError::Device(_))
        ));

        let non_block = furus_core::planner::DeviceProbe {
            path: "/tmp/not-a-block-device".to_string(),
            exists: true,
            block_device: false,
            error: None,
            facts: None,
        };
        assert!(matches!(
            furus_core::planner::device_ref(&non_block, false),
            Err(PlanError::Safety(_))
        ));
    }
}
