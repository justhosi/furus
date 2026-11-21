//! Boot-image file picker for the SELECT button (S32).
//!
//! The primary backend is the native XDG Desktop Portal `FileChooser`
//! interface, which works on Wayland/Omarchy sessions where legacy
//! `zenity`/`kdialog` helpers are absent. zbus 6 has no `blocking` module, so
//! [`pick_image_path`] drives one async block with `zbus::block_on` on whatever
//! thread the caller supplies (the UI hands this to a background worker).
//!
//! Two rules govern the fallback chain in [`resolve_chain`]:
//! * a user cancelling the portal dialog is a terminal `Cancelled` — we never
//!   pop a second dialog on top of a cancelled first one;
//! * only a technical `Unavailable` (no session bus, no portal service, a
//!   malformed reply) falls through to `zenity`/`kdialog`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use zbus::export::futures_core::Stream;
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

const PORTAL_DEST: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const FILE_CHOOSER_IFACE: &str = "org.freedesktop.portal.FileChooser";
const REQUEST_IFACE: &str = "org.freedesktop.portal.Request";

/// Monotonic token suffix so concurrent pickers never share a Request path.
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Result of asking the user for a boot image. `Unavailable` is the only
/// outcome that triggers the legacy fallback chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickerOutcome {
    Selected(PathBuf),
    Cancelled,
    Unavailable(String),
}

impl PickerOutcome {
    /// Whether the fallback chain should be attempted after this outcome.
    #[must_use]
    pub fn falls_through(&self) -> bool {
        matches!(self, PickerOutcome::Unavailable(_))
    }
}

/// Synchronous entry point. Runs the portal picker on the current thread and,
/// only if it is technically unavailable, tries the legacy helpers.
#[must_use]
pub fn pick_image_path() -> PickerOutcome {
    resolve_chain(pick_via_xdg_portal(), pick_via_fallbacks)
}

/// Run the primary portal picker. One `block_on` drives the whole async flow,
/// including waiting for the `Response` signal.
fn pick_via_xdg_portal() -> PickerOutcome {
    match zbus::block_on(portal_open()) {
        Ok(outcome) => outcome,
        Err(error) => PickerOutcome::Unavailable(format!(
            "XDG desktop portal unavailable: {error}"
        )),
    }
}

async fn portal_open() -> Result<PickerOutcome, zbus::Error> {
    let connection = zbus::Connection::session().await?;
    let unique_name = connection
        .unique_name()
        .map(|name| name.as_str().to_string())
        .unwrap_or_default();
    let token = format!(
        "furus_open_{}_{}",
        std::process::id(),
        REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let request_path = request_object_path(&unique_name, &token);

    // Subscribe to the Request's Response signal BEFORE calling OpenFile: a
    // fast portal must not emit the response in the gap between the method
    // reply and our subscription.
    let request =
        zbus::Proxy::new(&connection, PORTAL_DEST, request_path, REQUEST_IFACE).await?;
    let mut responses = request.receive_signal("Response").await?;

    let chooser =
        zbus::Proxy::new(&connection, PORTAL_DEST, PORTAL_PATH, FILE_CHOOSER_IFACE).await?;

    let boot_patterns: Vec<(u32, &str)> = [
        "*.iso", "*.img", "*.wim", "*.esd", "*.vhd", "*.vhdx", "*.raw", "*.bin", "*.gz",
        "*.xz", "*.zst", "*.bz2",
    ]
    .into_iter()
    .map(|pattern| (0, pattern))
    .collect();
    let filters: Vec<(&str, Vec<(u32, &str)>)> = vec![
        ("Boot images", boot_patterns),
        ("All files", vec![(0, "*")]),
    ];

    let mut options: HashMap<&str, Variant<'_>> = HashMap::new();
    options.insert("handle_token", Variant::from(token.as_str()));
    options.insert("modal", Variant::from(true));
    options.insert("multiple", Variant::from(false));
    options.insert("filters", Variant::from(filters));

    let _reply: OwnedObjectPath = chooser
        .call("OpenFile", &("", "Select boot image", options))
        .await?;

    // Stay inside the single outer block_on: poll the signal stream directly
    // instead of nesting another block_on on this thread.
    let message = std::future::poll_fn(|cx| {
        Stream::poll_next(std::pin::Pin::new(&mut responses), cx)
    })
    .await;
    let Some(message) = message else {
        return Ok(PickerOutcome::Unavailable(
            "portal returned no file URI".into(),
        ));
    };
    let (response, results): (u32, HashMap<String, OwnedVariant>) = message.body().deserialize()?;

    match response {
        0 => {
            let path = results
                .get("uris")
                .and_then(|value| match &**value {
                    Variant::Array(array) => array.iter().next(),
                    _ => None,
                })
                .and_then(|item| String::try_from(item).ok())
                .and_then(|uri| decode_file_uri(&uri));
            match path {
                Some(path) => Ok(PickerOutcome::Selected(path)),
                None => Ok(PickerOutcome::Unavailable(
                    "portal returned no file URI".into(),
                )),
            }
        }
        // 1 (cancel), 2 and any other code: the user's decision is final.
        _ => Ok(PickerOutcome::Cancelled),
    }
}

/// Build the well-known Request object path for a portal handle token.
/// A bus unique name such as `:1.42` becomes `1_42` in the path.
fn request_object_path(unique_name: &str, handle_token: &str) -> String {
    let owner = unique_name.strip_prefix(':').unwrap_or(unique_name);
    format!(
        "/org/freedesktop/portal/desktop/request/{}/{}",
        owner.replace('.', "_"),
        handle_token
    )
}

/// Decode a portal `file://` URI into a local absolute path. Percent escapes
/// are decoded to raw bytes and validated as UTF-8; `+`, `#` and `?` are never
/// given special meaning (the portal sends them percent-encoded).
fn decode_file_uri(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    if !rest.starts_with('/') {
        return None;
    }

    let bytes = rest.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = hex_value(*bytes.get(index + 1)?)?;
                let low = hex_value(*bytes.get(index + 2)?)?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).ok().map(PathBuf::from)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Return the fallback only when the primary attempt could not run. A real
/// user decision (`Selected`/`Cancelled`) is never second-guessed.
fn resolve_chain(
    primary: PickerOutcome,
    fallback: impl FnOnce() -> PickerOutcome,
) -> PickerOutcome {
    if primary.falls_through() {
        fallback()
    } else {
        primary
    }
}

/// Legacy helpers, used only when the portal is unavailable. Args mirror the
/// historical `pick_image_path()` in `main.rs`.
fn pick_via_fallbacks() -> PickerOutcome {
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
                return PickerOutcome::Selected(PathBuf::from(path));
            }
        }
    }
    PickerOutcome::Unavailable(
        "No file picker found: install xdg-desktop-portal (recommended), or zenity/kdialog. \
         You can also pass the image path directly: furus-gui /path/to/image.iso"
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::{PickerOutcome, decode_file_uri, request_object_path, resolve_chain};

    #[test]
    fn decode_file_uri_handles_spaces_utf8_and_reserved_characters() {
        assert_eq!(
            decode_file_uri("file:///home/user/My%20Images/boot%20image.iso"),
            Some("/home/user/My Images/boot image.iso".into())
        );
        assert_eq!(
            decode_file_uri("file:///home/user/caf%C3%A9.iso"),
            Some("/home/user/caf\u{e9}.iso".into())
        );
        assert_eq!(
            decode_file_uri("file:///home/user/a%23b%3Fc.iso"),
            Some("/home/user/a#b?c.iso".into())
        );
        assert_eq!(
            decode_file_uri("file:///home/user/plain.iso"),
            Some("/home/user/plain.iso".into())
        );
        assert_eq!(
            decode_file_uri("file:///home/user/a+b.iso"),
            Some("/home/user/a+b.iso".into())
        );
    }

    #[test]
    fn decode_file_uri_accepts_localhost_authority_and_rejects_bad_uris() {
        assert_eq!(
            decode_file_uri("file://localhost/home/user/boot.iso"),
            Some("/home/user/boot.iso".into())
        );
        assert_eq!(
            decode_file_uri("file://localhost/home/user/a%20b.iso"),
            Some("/home/user/a b.iso".into())
        );

        assert_eq!(decode_file_uri("http://example.com/boot.iso"), None);
        assert_eq!(decode_file_uri("/home/user/boot.iso"), None);
        assert_eq!(decode_file_uri("file://localhostrelative/boot.iso"), None);
        assert_eq!(decode_file_uri("file://%2Fhome/boot.iso"), None);
        assert_eq!(decode_file_uri("file:///home/%ZZ.iso"), None);
        assert_eq!(decode_file_uri("file:///home/%2.iso"), None);
        assert_eq!(decode_file_uri("file:///home/trailing%"), None);
        assert_eq!(decode_file_uri("file:///home/%FF.iso"), None);
    }

    #[test]
    fn request_object_path_transforms_the_unique_name() {
        assert_eq!(
            request_object_path(":1.42", "furus_open_1_0"),
            "/org/freedesktop/portal/desktop/request/1_42/furus_open_1_0"
        );
        assert_eq!(
            request_object_path(":1.1234", "token"),
            "/org/freedesktop/portal/desktop/request/1_1234/token"
        );
        assert_eq!(
            request_object_path("1.42", "token"),
            "/org/freedesktop/portal/desktop/request/1_42/token"
        );
    }

    #[test]
    fn resolve_chain_only_falls_through_on_unavailable() {
        let cancelled = resolve_chain(PickerOutcome::Cancelled, || panic!("must not fall back"));
        assert_eq!(cancelled, PickerOutcome::Cancelled);

        let selected = resolve_chain(PickerOutcome::Selected("/x.iso".into()), || {
            panic!("must not fall back")
        });
        assert_eq!(selected, PickerOutcome::Selected("/x.iso".into()));

        let unavailable = resolve_chain(PickerOutcome::Unavailable("no portal".into()), || {
            PickerOutcome::Selected("/fallback.iso".into())
        });
        assert_eq!(unavailable, PickerOutcome::Selected("/fallback.iso".into()));
    }

    #[test]
    fn falls_through_matches_only_unavailable() {
        assert!(PickerOutcome::Unavailable("x".into()).falls_through());
        assert!(!PickerOutcome::Cancelled.falls_through());
        assert!(!PickerOutcome::Selected("/x".into()).falls_through());
    }
}
