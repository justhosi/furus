//! Headless, unprivileged render smoke tests for the Slint shell.
//!
//! Slice S29-C2: instantiate `ui/main.slint` through the software renderer with
//! no window system and no root, push representative state (including every
//! conditionally-rendered overlay), render at least one frame, and assert that
//! nothing panics and that something was actually drawn. It deliberately
//! asserts no exact text metrics or colours — only deterministic offscreen
//! behaviour.
//!
//! Slice S33.8 adds a second scenario: render the destructive-confirm modal at
//! a realistic window size into an RGB buffer and assert that the centred
//! dialog card is not a solid monochrome box (several distinct colours from
//! its surface, text and buttons) and that it is bounded rather than stretched
//! over the full-height scrim. Together these guard the regression where an
//! unbounded dynamic overlay rendered as a blank white sheet.
//!
//! Lint note: this is a NEW integration-test binary that expands
//! `slint::include_modules!()`. Slint's generated code hardcodes
//! `#[allow(unsafe_code)]` (via `vtable-macro`'s `ItemTreeVTable_static!`),
//! which is the hard error E0453 under a crate-level `forbid`. So, exactly like
//! `src/main.rs`, this file uses `#![deny(unsafe_code)]` — NOT `forbid`. Every
//! hand-written line here is safe; only the macro expansions are exempt. The
//! workspace `[lints] unsafe_code = "deny"` is left untouched.

#![deny(unsafe_code)]

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::{Mutex, Once};

use slint::platform::software_renderer::{
    MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType, TargetPixel,
};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle, ModelRc, PhysicalSize, SharedString, VecModel};

slint::include_modules!();

const WIDTH: usize = 320;
const HEIGHT: usize = 240;

const CONFIRM_WIDTH: usize = 700;
const CONFIRM_HEIGHT: usize = 640;

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

/// A target pixel that keeps the *actual* composited RGB colour. `blend`
/// mirrors Slint's own `Rgb8Pixel` premultiplied-alpha composition so the
/// recorded value is what would really appear on screen. This lets the modal
/// test look for colour contrast instead of just "was anything drawn".
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
struct RgbPixel(u8, u8, u8);

impl TargetPixel for RgbPixel {
    fn blend(&mut self, color: PremultipliedRgbaColor) {
        let inverse_alpha = (u8::MAX - color.alpha) as u16;
        self.0 = (self.0 as u16 * inverse_alpha / 255) as u8 + color.red;
        self.1 = (self.1 as u16 * inverse_alpha / 255) as u8 + color.green;
        self.2 = (self.2 as u16 * inverse_alpha / 255) as u8 + color.blue;
    }

    fn from_rgb(red: u8, green: u8, blue: u8) -> Self {
        Self(red, green, blue)
    }
}

// Slint 1.19 keeps the installed platform in a *thread-local* context
// (`GLOBAL_CONTEXT`), so `set_platform` must be called once per test thread —
// a process-wide `Once` would leave the second test thread with no software
// adapter at all. A `Once` in thread-local storage gives each thread exactly
// one install. The software window is likewise thread-local so each component
// (which must live on its creating thread) gets its own adapter. A global
// mutex serializes the two scenarios so their rendering never overlaps.
thread_local! {
    static PLATFORM_INSTALLED: Once = const { Once::new() };
    static WINDOW: RefCell<Option<Rc<MinimalSoftwareWindow>>> = const { RefCell::new(None) };
}

static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Minimal platform that hands out the calling thread's offscreen window.
struct TestPlatform;

impl Platform for TestPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(current_window())
    }
}

fn install_platform_once() {
    PLATFORM_INSTALLED.with(|once| {
        once.call_once(|| {
            slint::platform::set_platform(Box::new(TestPlatform))
                .expect("install the headless software-renderer platform once per test thread");
        });
    });
}

/// Replace this thread's window with a fresh one (no state from an earlier
/// scenario) and return a clone the test can resize and render into.
fn fresh_window() -> Rc<MinimalSoftwareWindow> {
    let window = MinimalSoftwareWindow::new(RepaintBufferType::ReusedBuffer);
    WINDOW.with(|slot| *slot.borrow_mut() = Some(window.clone()));
    window
}

/// The window `create_window_adapter` handed to the component on this thread.
fn current_window() -> Rc<MinimalSoftwareWindow> {
    WINDOW.with(|slot| {
        slot.borrow()
            .as_ref()
            .expect("a test window must exist before a component is created")
            .clone()
    })
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
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_platform_once();
    let window = fresh_window();
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
    ui.set_volume_label(SharedString::from("FURUS"));
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

#[test]
fn confirm_modal_renders_with_contrast() {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_platform_once();
    let window = fresh_window();
    window.set_size(PhysicalSize::new(
        CONFIRM_WIDTH as u32,
        CONFIRM_HEIGHT as u32,
    ));

    let ui = MainWindow::new().expect("MainWindow must instantiate offscreen");
    ui.set_locale_model(strings(&["English"]));
    ui.set_locale_current(SharedString::from("English"));
    ui.set_device_model(strings(&["/dev/sdb — 8 GB"]));
    ui.set_device_current(SharedString::from("/dev/sdb — 8 GB"));
    ui.set_boot_model(strings(&["Standard"]));
    ui.set_boot_current(SharedString::from("Standard"));
    ui.set_scheme_model(strings(&["GPT"]));
    ui.set_scheme_current(SharedString::from("GPT"));
    ui.set_target_model(strings(&["UEFI"]));
    ui.set_target_current(SharedString::from("UEFI"));
    ui.set_fs_model(strings(&["FAT32"]));
    ui.set_fs_current(SharedString::from("FAT32"));
    ui.set_cluster_model(strings(&["32 KiB"]));
    ui.set_cluster_current(SharedString::from("32 KiB"));
    ui.set_passes_model(strings(&["1 pass"]));
    ui.set_passes_current(SharedString::from("1 pass"));

    // Only the confirm modal is visible. A concrete fact string makes the
    // dialog body non-empty so its Text node has glyphs to paint.
    ui.set_confirm_visible(true);
    ui.set_confirm_facts(SharedString::from("Device /dev/sdb will be erased."));

    ui.show()
        .expect("show must succeed on the offscreen window");
    slint::platform::update_timers_and_animations();
    ui.window().request_redraw();

    let mut buffer = vec![RgbPixel::default(); CONFIRM_WIDTH * CONFIRM_HEIGHT];
    let mut redrew = false;
    window.draw_if_needed(|renderer| {
        renderer.render(&mut buffer, CONFIRM_WIDTH);
        redrew = true;
    });
    assert!(
        redrew,
        "expected a pending redraw after show()/request_redraw()",
    );
    assert!(
        buffer.iter().any(|pixel| *pixel != RgbPixel::default()),
        "expected at least one drawn pixel (non-blank frame)"
    );

    // The dialog card is centred and at most 560px wide. Looking at the
    // central half of the window keeps the sample inside the card whether the
    // theme is light or dark. A solid monochrome box (the S33.8 regression)
    // would yield a single colour here; the card surface, themed foreground
    // text and buttons must produce several distinct ones.
    let mut colors = HashSet::new();
    for y in (CONFIRM_HEIGHT / 4)..(CONFIRM_HEIGHT * 3 / 4) {
        for x in (CONFIRM_WIDTH / 4)..(CONFIRM_WIDTH * 3 / 4) {
            colors.insert(buffer[y * CONFIRM_WIDTH + x]);
        }
    }
    assert!(
        colors.len() >= 3,
        "expected >= 3 distinct colours inside the dialog, got {}: {:?}",
        colors.len(),
        colors
    );

    // The card must be a bounded, centred dialog rather than a card stretched
    // over the whole window: the top-centre pixel sits on the dimming scrim,
    // while the window centre sits on the card surface. Equal colours would
    // mean the full-height regression from S33.8 is back.
    let top_center = buffer[10 * CONFIRM_WIDTH + CONFIRM_WIDTH / 2];
    let center = buffer[(CONFIRM_HEIGHT / 2) * CONFIRM_WIDTH + CONFIRM_WIDTH / 2];
    assert_ne!(
        top_center, center,
        "the dialog card must be centred and content-sized, not full-height"
    );

    ui.hide()
        .expect("hide must succeed on the offscreen window");
}
