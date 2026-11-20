//! Headless, unprivileged render smoke test for the Slint shell.
//!
//! Slice S29-C2: instantiate `ui/main.slint` through the software renderer with
//! no window system and no root, push representative state (including every
//! conditionally-rendered overlay), render at least one frame, and assert that
//! nothing panics and that something was actually drawn. It deliberately
//! asserts no exact text metrics or colours — only deterministic offscreen
//! behaviour.
//!
//! Lint note: this is a NEW integration-test binary that expands
//! `slint::include_modules!()`. Slint's generated code hardcodes
//! `#[allow(unsafe_code)]` (via `vtable-macro`'s `ItemTreeVTable_static!`),
//! which is the hard error E0453 under a crate-level `forbid`. So, exactly like
//! `src/main.rs`, this file uses `#![deny(unsafe_code)]` — NOT `forbid`. Every
//! hand-written line here is safe; only the macro expansions are exempt. The
//! workspace `[lints] unsafe_code = "deny"` is left untouched.

#![deny(unsafe_code)]

use std::rc::Rc;

use slint::platform::software_renderer::{
    MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType, TargetPixel,
};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle, ModelRc, PhysicalSize, SharedString, VecModel};

slint::include_modules!();

const WIDTH: usize = 320;
const HEIGHT: usize = 240;

/// A target pixel that only records whether *anything* was drawn over it.
/// Rendering text/widgets calls `blend`/`from_rgb`; an unused pixel stays
/// `false`, so a blank frame leaves the whole buffer `false`.
#[derive(Clone, Copy, Default)]
struct DrawnPixel(bool);

impl TargetPixel for DrawnPixel {
    fn blend(&mut self, _color: PremultipliedRgbaColor) {
        self.0 = true;
    }

    fn from_rgb(_red: u8, _green: u8, _blue: u8) -> Self {
        Self(true)
    }
}

/// Minimal platform that hands out one shared offscreen software window.
struct TestPlatform(Rc<MinimalSoftwareWindow>);

impl Platform for TestPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.0.clone())
    }
}

fn strings(items: &[&str]) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        items
            .iter()
            .map(|item| SharedString::from(*item))
            .collect::<Vec<_>>(),
    ))
}

#[test]
fn main_window_renders_offscreen_with_all_overlays() {
    // Install the platform before any component is instantiated, so the
    // component's window adapter is our software window rather than winit.
    let window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    slint::platform::set_platform(Box::new(TestPlatform(window.clone())))
        .expect("install the headless software-renderer platform once");
    window.set_size(PhysicalSize::new(WIDTH as u32, HEIGHT as u32));

    let ui = MainWindow::new().expect("MainWindow must instantiate offscreen");

    // Representative main-form state (scalars + the combo models that feed
    // the ComboBox bindings).
    ui.set_locale_model(strings(&["English"]));
    ui.set_locale_current(SharedString::from("English"));
    ui.set_device_model(strings(&["/dev/sdb — 8 GB"]));
    ui.set_device_current(SharedString::from("/dev/sdb — 8 GB"));
    ui.set_device_info(SharedString::from(
        "/dev/sdb — 8 GB — Model — Serial — /mnt",
    ));
    ui.set_boot_model(strings(&["Standard"]));
    ui.set_boot_current(SharedString::from("Standard"));
    ui.set_image_option_model(strings(&["DD image"]));
    ui.set_image_option_current(SharedString::from("DD image"));
    ui.set_image_option_visible(true);
    ui.set_scheme_model(strings(&["GPT"]));
    ui.set_scheme_current(SharedString::from("GPT"));
    ui.set_target_model(strings(&["UEFI"]));
    ui.set_target_current(SharedString::from("UEFI"));
    ui.set_fs_model(strings(&["FAT32"]));
    ui.set_fs_current(SharedString::from("FAT32"));
    ui.set_fs_enabled(true);
    ui.set_cluster_model(strings(&["32 KiB"]));
    ui.set_cluster_current(SharedString::from("32 KiB"));
    ui.set_passes_model(strings(&["1 pass"]));
    ui.set_passes_current(SharedString::from("1 pass"));
    ui.set_volume_label(SharedString::from("RUFUS"));
    ui.set_step_text(SharedString::from("Allocating"));
    ui.set_status_text(SharedString::from("Ready"));
    ui.set_log_text(SharedString::from("line one\nline two"));
    ui.set_progress_value(0.5);
    ui.set_form_enabled(true);
    ui.set_select_enabled(true);
    ui.set_checksum_enabled(true);
    ui.set_start_enabled(true);
    ui.set_cancel_enabled(true);

    // Exercise every conditionally-rendered overlay at once so their bindings
    // (including the `checksum-digests[0..3]` indexes) are evaluated. Rendering
    // all of them together is fine for a smoke test; it is not meant to mirror
    // a reachable user state.
    ui.set_advanced_visible(true);
    ui.set_hash_md5_checked(true);
    ui.set_hash_sha1_checked(true);
    ui.set_hash_sha256_checked(true);
    ui.set_hash_sha512_checked(true);
    ui.set_log_open(true);
    ui.set_confirm_visible(true);
    ui.set_confirm_facts(SharedString::from("Device /dev/sdb will be erased."));
    ui.set_checksum_visible(true);
    ui.set_checksum_digests(strings(&["d41d8cd9", "da39a3ee", "e3b0c442", "cf83e135"]));
    ui.set_checksum_status(SharedString::from("Hashing"));
    ui.set_checksum_progress(0.25);
    ui.set_checksum_cancel_enabled(true);

    ui.show()
        .expect("show must succeed on the offscreen window");
    slint::platform::update_timers_and_animations();
    ui.window().request_redraw();

    // Render into a fixed-size buffer. A true `draw_if_needed` proves a redraw
    // was pending; any non-default pixel proves the frame was non-blank.
    let mut buffer = vec![DrawnPixel(false); WIDTH * HEIGHT];
    let mut redrew = false;
    window.draw_if_needed(|renderer| {
        renderer.render(&mut buffer, WIDTH);
        redrew = true;
    });
    assert!(
        redrew,
        "expected a pending redraw after show()/request_redraw()"
    );
    assert!(
        buffer.iter().any(|pixel| pixel.0),
        "expected at least one drawn pixel (non-blank frame)"
    );

    ui.hide()
        .expect("hide must succeed on the offscreen window");
}
