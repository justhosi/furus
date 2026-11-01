//! UDF integration: drive the external `mkudffs` tool, then verify the
//! volume recognition sequence (S13, slice 1 of 3).
//!
//! PLAN lines 703-717 mandate UDF volumes built by shelling out to
//! `mkudffs --utf8 --media-type=hd --udfrev=0x0201 -b 512|2048 -l <label>`
//! (`--utf8` must come first, measured with udftools 2.3) under PLAN decision A4 (line 37), which keeps a curated set of
//! filesystems on external-tool formatters (the NTFS formatter of
//! [`fs::ntfs`] and the ext formatter of [`fs::ext`] ride on the same
//! decision) because a pure-Rust UDF writer is a multi-year project.
//! There is no native writer here and no dependency on `rufus-linux` /
//! `rufus-helper`: the tool path arrives as a spawn argument, the tool
//! runs as a bounded capture, and the only bytes this module parses are
//! the three 2048-byte volume recognition sectors at absolute bytes
//! 32768..38912 of the target.
//!
//! The recognition facts pinned below are two things and nothing else:
//! the UDF on-disk layout (the volume recognition sequence at byte 32768
//! — BEA01, one NSR descriptor, TEA01 — each a 2048-byte sector opening
//! with the struct type byte 0x00, five identifier bytes and the struct
//! version byte 0x01) and our own contract (the fixed `--udfrev=0x0201`
//! revision, which writes NSR03, and the 126-byte label ceiling). No
//! *conformance* claim is made here about real `mkudffs`, `udfinfo`,
//! mount or Windows behaviour; the tool-driving facts each cite the
//! measurements taken with udftools 2.3 inside the `archlinux:latest`
//! container during this slice, while mount and Windows acceptance stay
//! beyond this slice.
//!
//! Test discipline: `mkudffs` is absent from the dev host, so every test
//! below drives `#!/bin/sh` stubs or synthetic recognition regions and
//! claims nothing about real `mkudffs` output; the layout the synthetic
//! fixtures pin is the UDF on-disk format, not tool behaviour.

use std::fmt;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::tool;
use crate::log::Level;
use crate::log::Logger;
use crate::text::device_text;

/// Tool names in probe order: the canonical `mkudffs` first, then its
/// `mkfs.udf` alias (distros ship `mkfs.udf` as a symlink to the same
/// binary). [`find_tool`] probes the whole list — the "is there a UDF
/// formatter at all" question behind the wildcard hint.
const TOOL_NAMES: [&str; 2] = ["mkudffs", "mkfs.udf"];

/// The usage banner's first stderr line starts with this: `mkudffs` run
/// with no arguments prints `<tool name> from udftools <version>` to
/// stderr and exits 1 (measured with udftools 2.3, which ships no version
/// or help flag that succeeds — `--version` is an unrecognized option,
/// `-V` an invalid option, `--help` and `-h` exit 1). The probe treats a
/// candidate as present only when the banner matches this prefix; a
/// candidate that spawns but prints anything else is absent, like the
/// other families treat a failing probe.
const BANNER_PREFIX: &str = "mkudffs from udftools ";

/// Refusal when no usable UDF formatter is on `PATH`, one word per fact:
/// the hint names the tool and the package the UDF row of PLAN's
/// package-mapping table ships it in — `udftools` (the location varies by
/// distro: Debian uses `/usr/sbin`, while udftools 2.3 on Arch ships
/// `/usr/bin/mkudffs` with `/usr/bin/mkfs.udf -> mkudffs`) — in the shape
/// of the neighbouring ext row's hint in [`fs::ext`].
const MISSING_TOOL_HINT: &str = "no UDF formatter found (mkudffs): install the udftools package";

/// The UDF revision every format run pins as `--udfrev=0x0201` (the
/// mandate's revision): there is deliberately no knob for it, the same
/// reasoning that keeps ext's `-b 4096` fixed.
const UDF_REV_ARG: &str = "0x0201";

/// The NSR identifier the pinned revision writes: `--udfrev=0x0201`
/// yields NSR03 (measured with udftools 2.3; `--udfrev=0x0150` yields
/// NSR02 instead, which [`recognition`] refuses).
const EXPECTED_NSR: &str = "NSR03";

/// Byte ceiling of the `-l` label: 126 bytes are accepted, 127 refuse
/// with `mkudffs: Error: Option --label is too long` (measured with
/// udftools 2.3).
const LABEL_BYTES_MAX: usize = 126;

/// Absolute byte offset of the volume recognition sequence: three
/// consecutive 2048-byte sectors at a 2048-byte pitch for the two supported
/// block sizes (measured identical for `-b 512` and `2048` with udftools
/// 2.3; `-b 4096` spaces the descriptors 4096 bytes apart — BEA01 at 32768,
/// NSR03 at 36864, TEA01 at 40960 — which is exactly why [`BlockSize`]
/// offers only 512 and 2048; sector 19 (38912) is zero throughout).
const RECOGNITION_AT: usize = 32768;

/// One volume recognition sector in bytes.
const RECOGNITION_SECTOR_BYTES: usize = 2048;

/// The byte region [`format`] reads back: the three recognition sectors.
const RECOGNITION_BYTES: usize = 3 * RECOGNITION_SECTOR_BYTES;

/// One past the recognition region: the last byte the parser reads, so a
/// buffer shorter than this cannot carry the full sequence.
const RECOGNITION_END: usize = RECOGNITION_AT + RECOGNITION_BYTES;

/// Locate the UDF formatter over `PATH` without narrowing: `mkudffs`,
/// falling back to `mkfs.udf`.
///
/// Each `PATH` directory is scanned by hand (existence plus the owner
/// execute bit — never a shell, never a `PATH` mutation), and the first
/// candidate whose banner probe matches [`BANNER_PREFIX`] wins; a
/// candidate whose probe fails is treated as absent. This answers "is
/// there any UDF formatter at all" (the scan is the shared
/// [`tool::scan_candidates_with`] — no TOCTOU).
pub fn find_tool() -> Result<&'static str> {
    probe_candidates(&tool::path_dirs(), &TOOL_NAMES).map(|(name, _)| name)
}

/// [`find_tool`] over an explicit directory list, so tests can point the
/// probe at scratch directories without touching the process environment
/// (`std::env::set_var` is `unsafe` under this crate's edition and the
/// crate keeps `#![forbid(unsafe_code)]`, which leaves no room for it).
fn find_tool_in(dirs: &[PathBuf]) -> Result<(&'static str, PathBuf)> {
    probe_candidates(dirs, &TOOL_NAMES)
}

/// Probe `names` in order over `dirs`, returning the first entry that is an
/// executable file whose banner probe matches; nothing found, nothing
/// executable, or a probe that ran and failed reports the shared
/// [`MISSING_TOOL_HINT`] refusal. A probe that could not be spawned at all
/// (other than a vanishing `NotFound`) refuses as an I/O error naming the
/// candidate path, never the package hint.
///
/// The banner shape is why this family cannot share the flag probe: every
/// `mkudffs` flag exits non-zero (see [`BANNER_PREFIX`]), so the scan runs
/// through [`tool::scan_candidates_with`] with [`probe_banner_present`].
fn probe_candidates(dirs: &[PathBuf], names: &[&'static str]) -> Result<(&'static str, PathBuf)> {
    tool::scan_candidates_with(dirs, names, probe_banner_present, missing_tool_error)
}

/// The banner predicate behind [`probe_candidates`]: the candidate is
/// present only when [`tool::probe_banner`] returns the `mkudffs from
/// udftools ` usage banner. A stub that exits 0 or prints any other first
/// line is absent; a spawn error other than `NotFound` stays an honest
/// I/O error at the scan, never the package hint.
fn probe_banner_present(candidate: &Path) -> std::io::Result<bool> {
    match tool::probe_banner(candidate)? {
        Some(line) => Ok(line.starts_with(BANNER_PREFIX)),
        None => Ok(false),
    }
}

/// The shared refusal for an absent formatter: nothing found, nothing
/// executable, or a probe that ran and failed. Spawn failures refuse as I/O
/// errors instead, so every "the toolchain is missing" path names the same
/// package without hiding an honest spawn error.
fn missing_tool_error() -> CoreError {
    CoreError::invalid(MISSING_TOOL_HINT)
}

/// The `-b` block size a format run passes: 512 or 2048 bytes (both
/// measured formatting successfully with udftools 2.3 — `-b 4096`
/// formats too, but the mandate pins the choice to these two).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSize {
    /// 512-byte blocks.
    Bytes512,
    /// 2048-byte blocks.
    Bytes2048,
}

impl BlockSize {
    /// The `-b` spawn token: `512` or `2048`.
    #[must_use]
    pub fn as_bytes(&self) -> u32 {
        match self {
            Self::Bytes512 => 512,
            Self::Bytes2048 => 2048,
        }
    }
}

/// The write-side options of [`format`]: the block size and an optional
/// label. The UDF revision is fixed by the mandate (`--udfrev=0x0201`)
/// and is not an option at all — there is deliberately no knob for it.
#[derive(Debug, Clone)]
pub struct Options {
    /// Block size passed as `mkudffs -b`; see [`BlockSize`].
    pub block_bytes: BlockSize,
    /// Volume label passed as `mkudffs -l`; `None` omits the flag entirely.
    /// Validated by [`Options::with_label`]: at most 126 bytes.
    pub label: Option<String>,
}

impl Options {
    /// Options with no label; see [`Options::with_label`] to attach a
    /// validated one.
    #[must_use]
    pub fn new(block_bytes: BlockSize) -> Self {
        Self {
            block_bytes,
            label: None,
        }
    }

    /// Attach a volume label, refused unless it is at most 126 bytes —
    /// the tool refuses 127 bytes with `Option --label is too long`
    /// (measured with udftools 2.3), and the refusal names both numbers.
    /// Non-ASCII is allowed because every run passes `--utf8` (measured:
    /// a UTF-8 label with spaces and symbols formats); the refusal echoes
    /// no label bytes, only the length. An empty label is stored as-is
    /// and passed as `-l ""`, which the tool accepts (measured): there is
    /// no empty special case, `None` is the only way to omit `-l`.
    pub fn with_label(mut self, label: impl Into<String>) -> Result<Self> {
        let label = label.into();
        let length = label.len();
        if length > LABEL_BYTES_MAX {
            return Err(CoreError::invalid(format!(
                "udf label is {length} bytes long: the label must be at most \
                 {LABEL_BYTES_MAX} bytes (mkudffs refuses 127 bytes with `Option --label \
                 is too long`, measured with udftools 2.3)"
            )));
        }
        self.label = Some(label);
        Ok(self)
    }
}

/// The NSR descriptor the recognition sequence carries: the pinned
/// `--udfrev=0x0201` revision writes `NSR03`, while `--udfrev=0x0150`
/// writes `NSR02` (both measured with udftools 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nsr {
    /// `NSR02`: refused by [`recognition`] as a revision mismatch — the
    /// variant exists so the mismatch names what was found.
    Nsr02,
    /// `NSR03`: the only accepted identifier, written by the pinned
    /// `--udfrev=0x0201` revision.
    Nsr03,
}

impl Nsr {
    /// The on-disk identifier: `"NSR02"` or `"NSR03"`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nsr02 => "NSR02",
            Self::Nsr03 => "NSR03",
        }
    }
}

impl fmt::Display for Nsr {
    /// The on-disk identifier (`NSR02`, `NSR03`) — the same word refusals
    /// and summaries name the descriptor by.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// The verified recognition sequence [`format`] reads back from the
/// target: the parsed on-disk fact, screened by the revision invariant
/// ([`recognition`] only ever returns [`Nsr::Nsr03`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recognition {
    /// The NSR identifier the sequence carries.
    pub nsr: Nsr,
}

/// Verify the UDF volume recognition sequence inside a three-sector byte
/// region.
///
/// `region` is the 6144 bytes at absolute target bytes 32768..38912 (as
/// [`format`] reads them): the on-disk layout holds three consecutive
/// 2048-byte sectors there — BEA01, one NSR descriptor, TEA01 — so the
/// sector reads run at absolute offsets 32768, 34816 and 36864. `Ok`
/// requires, in order:
///
/// * the region reaches through byte [`RECOGNITION_END`] — a shorter
///   buffer has no complete sequence to read, and the refusal names the
///   needed byte count;
/// * byte 0 of each sector is the struct type `0x00`, named when wrong;
/// * bytes 1..6 are the ASCII identifier `BEA01` (offset 32768), `NSR03`
///   (34816), `TEA01` (36864), named with the found bytes when wrong;
/// * byte 6 of each sector is the struct version `0x01`, named when wrong;
/// * the 34816 identifier is `NSR03`: `NSR02` refuses naming the revision
///   mismatch (the pinned `--udfrev=0x0201` writes NSR03; NSR02 belongs to
///   `--udfrev=0x0150`, measured with udftools 2.3).
///
/// The offsets and shapes pinned here are the UDF on-disk layout plus
/// this house's contract; real `mkudffs` behaviour is not claimed (see
/// the module header's test discipline).
pub fn recognition(region: &[u8]) -> Result<Recognition> {
    let length = region.len();
    if length < RECOGNITION_BYTES {
        return Err(CoreError::invalid(format!(
            "the UDF recognition region is {length} bytes but the on-disk layout \
             needs {RECOGNITION_BYTES}: the three 2048-byte volume recognition sectors \
             run from byte {RECOGNITION_AT} to byte {RECOGNITION_END}"
        )));
    }
    check_sector(region, 0, "BEA01")?;
    let nsr = check_nsr(region)?;
    check_sector(region, 2, "TEA01")?;
    Ok(Recognition { nsr })
}

/// Check one recognition sector's type byte, ASCII identifier and version
/// byte: sector `index` (0 or 2) starts at absolute byte
/// `RECOGNITION_AT + index * 2048`, and every refusal names that absolute
/// offset with the found bytes and the expected identifier.
fn check_sector(region: &[u8], index: usize, expected: &str) -> Result<()> {
    let base = index * RECOGNITION_SECTOR_BYTES;
    let start = RECOGNITION_AT + base;
    check_type_byte(region, base, start)?;
    let identifier = sector_identifier(region, base, start)?;
    if identifier != expected {
        return Err(identifier_mismatch(start, &identifier, expected));
    }
    check_version_byte(region, base, start)?;
    Ok(())
}

/// Check the middle recognition sector (absolute byte 34816): the type
/// and version bytes read like every sector, while the identifier must be
/// the pinned revision's NSR03 — NSR02 refuses naming the revision
/// mismatch, anything else refuses naming the expected identifier.
fn check_nsr(region: &[u8]) -> Result<Nsr> {
    const NSR_INDEX: usize = 1;
    let base = NSR_INDEX * RECOGNITION_SECTOR_BYTES;
    let start = RECOGNITION_AT + base;
    check_type_byte(region, base, start)?;
    let identifier = sector_identifier(region, base, start)?;
    if identifier == EXPECTED_NSR {
        check_version_byte(region, base, start)?;
        return Ok(Nsr::Nsr03);
    }
    if identifier == Nsr::Nsr02.as_str() {
        return Err(CoreError::invalid(format!(
            "the UDF recognition sector at byte {start} reads `{}` not `NSR03`: \
             the fixed --udfrev={UDF_REV_ARG} revision writes NSR03 (NSR02 belongs to \
             --udfrev=0x0150, measured with udftools 2.3), refusing on the revision mismatch",
            Nsr::Nsr02,
        )));
    }
    Err(identifier_mismatch(start, &identifier, EXPECTED_NSR))
}

/// Byte 0 of the sector at region offset `base` (absolute `start`) is the
/// struct type `0x00`: the refusal names the absolute offset, the found
/// byte and the expected value.
fn check_type_byte(region: &[u8], base: usize, start: usize) -> Result<()> {
    let found = region.get(base).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "the UDF recognition region ends before the struct type byte at byte {start}"
        ))
    })?;
    if found != 0x00 {
        return Err(CoreError::invalid(format!(
            "the UDF recognition sector at byte {start} has struct type 0x{found:02X} \
             not 0x00: byte {start} must read 0x00"
        )));
    }
    Ok(())
}

/// Bytes 1..6 of the sector at region offset `base` (absolute `start`) as
/// sanitised text, for identifier comparisons and refusals (non-ASCII
/// becomes `?` through the one device-text sanitiser, so refusals stay
/// ASCII whatever bytes the target holds).
fn sector_identifier(region: &[u8], base: usize, start: usize) -> Result<String> {
    let bytes = region.get(base + 1..base + 6).ok_or_else(|| {
        CoreError::invalid(format!(
            "the UDF recognition region ends before the identifier bytes {}..{} \
             of the sector at byte {start}",
            start + 1,
            start + 6,
        ))
    })?;
    Ok(device_text(&String::from_utf8_lossy(bytes)))
}

/// Byte 6 of the sector at region offset `base` (absolute `start`) is the
/// struct version `0x01`: the refusal names the absolute offset, the found
/// byte and the expected value.
fn check_version_byte(region: &[u8], base: usize, start: usize) -> Result<()> {
    let at = start + 6;
    let found = region.get(base + 6).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "the UDF recognition region ends before the struct version byte at byte {at}"
        ))
    })?;
    if found != 0x01 {
        return Err(CoreError::invalid(format!(
            "the UDF recognition sector at byte {start} has struct version 0x{found:02X} \
             not 0x01: byte {at} must read 0x01"
        )));
    }
    Ok(())
}

/// Refusal for a recognition sector whose identifier is not `expected`:
/// names the absolute sector offset, the found bytes and the expected
/// identifier.
fn identifier_mismatch(start: usize, found: &str, expected: &str) -> CoreError {
    CoreError::invalid(format!(
        "the UDF recognition sector at byte {start} reads `{found}` not `{expected}`: \
         bytes {}..{} must read the {expected} identifier",
        start + 1,
        start + 6,
    ))
}

/// Refuse a missing target before any tool runs: a UDF format needs an
/// existing target — `mkudffs` refuses to create one without a
/// block count (`Cannot create new image file`, measured with udftools
/// 2.3). The refusal names the path through the one device-text
/// sanitiser, so it stays ASCII.
fn check_target_exists(target: &Path) -> Result<()> {
    if target.exists() {
        return Ok(());
    }
    Err(CoreError::invalid(format!(
        "the UDF target `{}` does not exist: formatting needs an existing \
         target (mkudffs refuses to create one without a block count, \
         measured with udftools 2.3)",
        device_text(&target.display().to_string())
    )))
}

/// Format `target` as UDF with the external formatter.
///
/// Refuses a missing target before any tool runs (see
/// [`check_target_exists`]), then runs
/// `mkudffs --utf8 --media-type=hd --udfrev=0x0201 -b <512|2048> [-l <label>]
/// <target>` (`--utf8` is first because the tool refuses it in any other
/// position, measured with udftools 2.3; the target path is always the
/// last argument) as a bounded capture — both streams piped and drained
/// via `output()`, `LC_ALL=C` in the child environment — then reads back
/// absolute bytes 32768..38912 and verifies them with [`recognition`].
/// Every non-empty captured line (stdout then stderr, each through the one
/// device-text sanitiser) is logged verbatim at `Info` under the `udf`
/// target; a failing exit becomes a refusal naming the tool, the status
/// and the last [`tool::MAX_TAIL_LINES`] stderr lines (a small-target warning with exit 0 is a
/// warning, not a failure). On success the summary is the snapshot's final
/// line and the verified NSR comes back as a [`Recognition`].
pub fn format(target: &Path, options: &Options, logger: &Logger) -> Result<Recognition> {
    // The missing-target rule runs before the probe: a refusal must not
    // even run the banner probe, let alone format anything.
    check_target_exists(target)?;
    let (tool, tool_path) = find_tool_in(&tool::path_dirs())?;
    format_with(target, options, logger, tool, &tool_path)
}

/// [`format`] with the tool already resolved, so tests can point the run at
/// a stub by absolute path without touching the process environment.
fn format_with(
    target: &Path,
    options: &Options,
    logger: &Logger,
    tool: &'static str,
    tool_path: &Path,
) -> Result<Recognition> {
    // The missing-target rule runs before the formatter spawns: the stub
    // tests pin that a missing target never invokes the tool at all.
    check_target_exists(target)?;
    let mut command = Command::new(tool_path);
    command
        .arg("--utf8")
        .arg("--media-type=hd")
        .arg(format!("--udfrev={UDF_REV_ARG}"))
        .arg("-b")
        .arg(options.block_bytes.as_bytes().to_string());
    if let Some(label) = options.label.as_deref() {
        command.arg("-l").arg(label);
    }
    command.arg(target);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C");
    // Bounded capture: the tool is this slice's external mandate (PLAN
    // lines 703-717), and `output` drains both pipes so a chatty tool
    // cannot block on a full buffer.
    let output =
        tool::output_retrying(&mut command).map_err(|error| CoreError::io(tool_path, error))?;

    let stderr_lines = tool::captured_lines(&output.stderr);
    tool::log_captured_lines(logger, "udf", &output);

    if !output.status.success() {
        return Err(tool::output_failure(
            tool,
            &output.status.to_string(),
            &stderr_lines,
        ));
    }

    let verified = recognition(&read_recognition(target)?)?;
    log_format_summary(logger, tool, &output.status.to_string(), options, &verified);
    Ok(verified)
}

/// Log the format success summary at `Info` under the `udf` target: the
/// tool, its exit, the block size, the label and the NSR identifier — the
/// snapshot's final line on every successful [`format`].
fn log_format_summary(
    logger: &Logger,
    tool: &str,
    status: &str,
    options: &Options,
    verified: &Recognition,
) {
    let label_text = match &options.label {
        Some(name) => format!("label `{}`", device_text(name)),
        None => "no label".to_string(),
    };
    logger.log(
        Level::Info,
        "udf",
        &format!(
            "{tool} finished ({status}): verified UDF volume with {} byte blocks, \
             {label_text} and {}",
            options.block_bytes.as_bytes(),
            verified.nsr,
        ),
    );
}

/// Read absolute bytes 32768..38912 of `target` — the three volume
/// recognition sectors — for [`recognition`] verification.
fn read_recognition(target: &Path) -> Result<[u8; RECOGNITION_BYTES]> {
    let file = std::fs::File::open(target).map_err(|err| CoreError::io(target, err))?;
    let mut region = [0u8; RECOGNITION_BYTES];
    file.read_exact_at(&mut region, RECOGNITION_AT as u64)
        .map_err(|err| CoreError::io(target, err))?;
    Ok(region)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Build a synthetic three-sector recognition region: BEA01, the given
    /// NSR identifier, TEA01 — each sector a 0x00 type byte, five ASCII
    /// identifier bytes, a 0x01 version byte and zero padding to 2048
    /// bytes. Stub/synthetic only: pins the layout this module parses,
    /// claims nothing about real `mkudffs` output.
    fn synthetic_region(nsr: &str) -> [u8; RECOGNITION_BYTES] {
        let mut region = [0u8; RECOGNITION_BYTES];
        for (index, identifier) in ["BEA01", nsr, "TEA01"].iter().enumerate() {
            let base = index * RECOGNITION_SECTOR_BYTES;
            region[base] = 0x00;
            region[base + 1..base + 6].copy_from_slice(identifier.as_bytes());
            region[base + 6] = 0x01;
        }
        region
    }

    /// Write a synthetic target image: zeroes with the synthetic
    /// recognition region at byte 32768, so [`format_with`] stubs read
    /// back real-shape bytes they never wrote themselves.
    fn write_target(dir: &Path, name: &str, region: &[u8; RECOGNITION_BYTES]) -> PathBuf {
        let mut image = vec![0u8; RECOGNITION_END];
        image[RECOGNITION_AT..RECOGNITION_END].copy_from_slice(region);
        let target = dir.join(name);
        std::fs::write(&target, &image).expect("the synthetic target writes");
        target
    }

    /// Write an executable `#!/bin/sh` stub into `dir`. Stub behaviour
    /// only: exercises the probe/spawn plumbing, never the real tool.
    fn write_stub(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("the stub writes");
        let mut permissions = std::fs::metadata(&path)
            .expect("the stub exists")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("the stub is executable");
        path
    }

    /// The discovery tests inject scratch directories (see
    /// [`find_tool_in`]): no test here mutates the process environment,
    /// so every test in this module runs in parallel safely.
    fn probe_dirs(dir: &Path) -> Vec<PathBuf> {
        vec![dir.to_path_buf()]
    }

    #[test]
    fn block_sizes_pin_their_spawn_tokens() {
        assert_eq!(BlockSize::Bytes512.as_bytes(), 512);
        assert_eq!(BlockSize::Bytes2048.as_bytes(), 2048);
        let options = Options::new(BlockSize::Bytes512);
        assert_eq!(options.block_bytes, BlockSize::Bytes512);
        assert_eq!(options.label, None);
    }

    #[test]
    fn options_label_pins_the_126_byte_ceiling() {
        let full = "A".repeat(LABEL_BYTES_MAX);
        let accepted = Options::new(BlockSize::Bytes2048)
            .with_label(full.clone())
            .expect("126 bytes fit the label");
        assert_eq!(accepted.label.as_deref(), Some(full.as_str()));

        let too_long = "A".repeat(LABEL_BYTES_MAX + 1);
        let error = Options::new(BlockSize::Bytes2048)
            .with_label(too_long)
            .expect_err("127 bytes refuse");
        let text = error.to_string();
        assert!(text.contains("127"), "{text}");
        assert!(text.contains("126"), "{text}");

        // No empty-label special case: an empty string is stored as an
        // empty label (the tool accepts `-l ""`), while `None` omits `-l`.
        let empty = Options::new(BlockSize::Bytes512)
            .with_label("")
            .expect("an empty label is stored as-is");
        assert_eq!(empty.label.as_deref(), Some(""));
    }

    #[test]
    fn probe_accepts_the_udftools_banner() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let stub = write_stub(
            scratch.path(),
            "mkudffs",
            "#!/bin/sh\necho 'mkudffs from udftools 9.9' >&2\nexit 1\n",
        );
        let (name, path) = find_tool_in(&probe_dirs(scratch.path())).expect("the banner probes");
        assert_eq!(name, "mkudffs");
        assert_eq!(path, stub);
    }

    #[test]
    fn probe_rejects_a_zero_exit() {
        // A stub that prints the banner but exits 0: only the exit code can
        // reject it, the same package error as the empty directory list.
        // Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        write_stub(
            scratch.path(),
            "mkudffs",
            "#!/bin/sh\necho 'mkudffs from udftools 9.9' >&2\nexit 0\n",
        );
        let error =
            find_tool_in(&probe_dirs(scratch.path())).expect_err("a bannerless probe is absent");
        assert_eq!(
            error.to_string(),
            format!("invalid input: {MISSING_TOOL_HINT}"),
        );
    }

    #[test]
    fn probe_rejects_a_foreign_banner() {
        // A stub that exits 1 with another family's first line: absent,
        // the same package error. Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        write_stub(
            scratch.path(),
            "mkudffs",
            "#!/bin/sh\necho 'mke2fs 1.47.4 (never-a-banner)' >&2\nexit 1\n",
        );
        let error =
            find_tool_in(&probe_dirs(scratch.path())).expect_err("a foreign banner is absent");
        assert_eq!(
            error.to_string(),
            format!("invalid input: {MISSING_TOOL_HINT}"),
        );
    }

    #[test]
    fn probe_prefers_mkudffs_and_falls_back_to_mkfs_udf() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let banner = "#!/bin/sh\necho 'mkudffs from udftools 9.9' >&2\nexit 1\n";
        write_stub(scratch.path(), "mkfs.udf", banner);
        let (alias, _) = find_tool_in(&probe_dirs(scratch.path())).expect("the alias probes");
        assert_eq!(alias, "mkfs.udf");
        write_stub(scratch.path(), "mkudffs", banner);
        let (canonical, _) = find_tool_in(&probe_dirs(scratch.path())).expect("a stub probes");
        assert_eq!(canonical, "mkudffs");
    }

    #[test]
    fn probe_with_no_directories_names_the_package() {
        let error = find_tool_in(&[]).expect_err("nothing can be found");
        assert_eq!(
            error.to_string(),
            format!("invalid input: {MISSING_TOOL_HINT}"),
            "the empty-PATH text is pinned exactly"
        );
    }

    #[test]
    fn format_pins_the_exact_argv_order() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let record = scratch.path().join("args");
        let body = format!(
            "#!/bin/sh\nprintf '<%s>' \"$@\" > '{}'\nexit 0\n",
            record.display()
        );
        let tool_path = write_stub(scratch.path(), "mkudffs", &body);
        // The stub never touches the target bytes: the target already
        // carries the synthetic recognition sequence the read-back
        // verifies.
        let target = write_target(scratch.path(), "volume.bin", &synthetic_region("NSR03"));
        let logger = Logger::new(Level::Trace);
        let options = Options::new(BlockSize::Bytes512)
            .with_label("MY LABEL")
            .expect("the label is valid");

        let verified = format_with(&target, &options, &logger, "mkudffs", &tool_path)
            .expect("the stub exits 0");
        assert_eq!(verified.nsr, Nsr::Nsr03);

        // `--utf8` first, then `--media-type=hd`, `--udfrev=0x0201`,
        // `-b 512`, `-l <label>`, the target last — one `<%s>` group per
        // argv element, so the order and the splitting are both pinned.
        let recorded = std::fs::read_to_string(&record).expect("the stub recorded");
        let expected = format!(
            "<--utf8><--media-type=hd><--udfrev=0x0201><-b><512><-l><MY LABEL><{}>",
            target.display()
        );
        assert_eq!(recorded, expected);

        let snapshot = logger.snapshot();
        assert!(
            snapshot
                .iter()
                .all(|record| record.target == "udf" && record.level == Level::Info),
            "every line is logged at Info under the udf target"
        );
        let messages: Vec<&str> = snapshot
            .iter()
            .map(|record| record.message.as_str())
            .collect();
        // The final line names the tool, the exit, the block size, the
        // label and the NSR identifier.
        let summary = messages.last().expect("the summary is logged");
        assert!(summary.contains("mkudffs"), "{summary}");
        assert!(summary.contains("exit status: 0"), "{summary}");
        assert!(summary.contains("512"), "{summary}");
        assert!(summary.contains("label `MY LABEL`"), "{summary}");
        assert!(summary.contains("NSR03"), "{summary}");
    }

    #[test]
    fn format_omits_the_label_flag_when_unlabeled() {
        // The `label == None` branch sends no `-l` at all: the recorded
        // argv jumps from `-b 2048` straight to the target.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let record = scratch.path().join("args");
        let body = format!(
            "#!/bin/sh\nprintf '<%s>' \"$@\" > '{}'\nexit 0\n",
            record.display()
        );
        let tool_path = write_stub(scratch.path(), "mkudffs", &body);
        let target = write_target(scratch.path(), "volume.bin", &synthetic_region("NSR03"));
        let logger = Logger::new(Level::Trace);
        let options = Options::new(BlockSize::Bytes2048);

        let verified = format_with(&target, &options, &logger, "mkudffs", &tool_path)
            .expect("the stub exits 0");
        assert_eq!(verified.nsr, Nsr::Nsr03);

        let recorded = std::fs::read_to_string(&record).expect("the stub recorded");
        let expected = format!(
            "<--utf8><--media-type=hd><--udfrev=0x0201><-b><2048><{}>",
            target.display()
        );
        assert_eq!(recorded, expected);

        let snapshot = logger.snapshot();
        let summary = snapshot
            .last()
            .expect("the summary is logged")
            .message
            .clone();
        assert!(summary.contains("no label"), "{summary}");
    }

    #[test]
    fn format_failure_carries_the_status_and_the_tail() {
        // A stub that exits 3 after ten stderr lines: the refusal names the
        // tool and the status and carries only the last 8 stderr lines.
        // Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(
            scratch.path(),
            "mkudffs",
            "#!/bin/sh\necho l01 >&2\necho l02 >&2\necho l03 >&2\necho l04 >&2\necho l05 >&2\n\
             echo l06 >&2\necho l07 >&2\necho l08 >&2\necho l09 >&2\necho l10 >&2\n\
             exit 3\n",
        );
        // The target exists so the run reaches the tool: the failure below
        // is the tool exit, never the missing-target refusal.
        let target = write_target(scratch.path(), "volume.bin", &synthetic_region("NSR03"));
        let logger = Logger::new(Level::Trace);
        let options = Options::new(BlockSize::Bytes512);

        let error = format_with(&target, &options, &logger, "mkudffs", &tool_path)
            .expect_err("the stub exits 3");
        let text = error.to_string();
        assert!(text.contains("mkudffs"), "{text}");
        assert!(text.contains("exit status: 3"), "{text}");
        assert!(text.contains("l10"), "{text}");
        assert!(text.contains("l03"), "{text}");
        assert!(!text.contains("l01"), "{text}");
        assert!(!text.contains("l02"), "{text}");
    }

    #[test]
    fn format_refuses_a_missing_target_before_any_tool_runs() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let record = scratch.path().join("args");
        let body = format!(
            "#!/bin/sh\nprintf '<%s>' \"$@\" > '{}'\nexit 0\n",
            record.display()
        );
        let tool_path = write_stub(scratch.path(), "mkudffs", &body);
        // No target file is created: the run must refuse before spawning.
        let target = scratch.path().join("missing.bin");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(BlockSize::Bytes2048);

        let error = format_with(&target, &options, &logger, "mkudffs", &tool_path)
            .expect_err("a missing target refuses");
        let text = error.to_string();
        assert!(text.contains("does not exist"), "{text}");
        assert!(text.contains("missing.bin"), "{text}");
        assert!(
            !record.exists(),
            "the stub never ran, not even the probe: the refusal precedes every tool invocation"
        );

        // The public entry refuses the same way even with the real
        // toolchain on PATH: the missing-target rule precedes the probe.
        let error = format(&target, &options, &logger).expect_err("format refuses before probing");
        let text = error.to_string();
        assert!(text.contains("does not exist"), "{text}");
        assert!(text.contains("missing.bin"), "{text}");
    }

    #[test]
    fn recognition_accepts_the_three_sector_fixture() {
        let region = synthetic_region("NSR03");
        let verified = recognition(&region).expect("the synthetic region parses");
        assert_eq!(verified.nsr, Nsr::Nsr03);
        assert_eq!(verified.nsr.as_str(), "NSR03");
        assert_eq!(verified.nsr.to_string(), "NSR03");
    }

    #[test]
    fn recognition_refuses_nsr02_as_a_revision_mismatch() {
        let region = synthetic_region("NSR02");
        let error = recognition(&region).expect_err("NSR02 is a revision mismatch");
        let text = error.to_string();
        assert!(text.contains("34816"), "{text}");
        assert!(text.contains("NSR02"), "{text}");
        assert!(text.contains("NSR03"), "{text}");
        assert!(text.contains("0x0201"), "{text}");
        assert!(text.contains("mismatch"), "{text}");
    }

    #[test]
    fn recognition_refuses_a_wrong_identifier() {
        let mut region = synthetic_region("NSR03");
        region[RECOGNITION_SECTOR_BYTES + 1..RECOGNITION_SECTOR_BYTES + 6]
            .copy_from_slice(b"XXX01");
        let error = recognition(&region).expect_err("XXX01 is not an NSR identifier");
        let text = error.to_string();
        assert!(text.contains("34816"), "{text}");
        assert!(text.contains("XXX01"), "{text}");
        assert!(text.contains("NSR03"), "{text}");
    }

    #[test]
    fn recognition_refuses_a_wrong_type_byte() {
        let mut region = synthetic_region("NSR03");
        region[0] = 0x01;
        let error = recognition(&region).expect_err("0x01 is not the struct type");
        let text = error.to_string();
        assert!(text.contains("32768"), "{text}");
        assert!(text.contains("0x01"), "{text}");
        assert!(text.contains("0x00"), "{text}");
    }

    #[test]
    fn recognition_refuses_a_wrong_version_byte() {
        // The struct version byte is offset 6 of each sector: the first
        // sector starts at 32768, so its version byte is 32774.
        let mut region = synthetic_region("NSR03");
        region[6] = 0x02;
        let error = recognition(&region).expect_err("0x02 is not the struct version");
        let text = error.to_string();
        assert!(text.contains("32768"), "{text}");
        assert!(text.contains("32774"), "{text}");
        assert!(text.contains("0x02"), "{text}");
        assert!(text.contains("0x01"), "{text}");
    }

    #[test]
    fn recognition_refuses_a_short_region() {
        let region = vec![0u8; 100];
        let error = recognition(&region).expect_err("100 bytes carry no sequence");
        let text = error.to_string();
        assert!(text.contains("100"), "{text}");
        assert!(text.contains("6144"), "{text}");
    }

    #[test]
    fn format_writes_the_recognition_sequence_for_both_block_sizes() {
        // A stub that records its argv, parses its own -b value, writes
        // the three descriptors at the measured offsets and exits 0.
        // Stub behaviour only: the shape it writes is the on-disk layout,
        // not a claim about the real tool.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let log = scratch.path().join("argv.log");
        let body = format!(
            "#!/bin/sh\nprintf '<%s>' \"$@\" >> '{}'\nprintf '\\n' >> '{}'\nprev=\"\"\nlast=\"\"\nb=\"\"\nfor a in \"$@\"; do\nif [ \"$prev\" = \"-b\" ]; then b=\"$a\"; fi\nprev=\"$a\"\nlast=\"$a\"\ndone\nif [ \"$b\" != \"512\" ] && [ \"$b\" != \"2048\" ]; then exit 1; fi\nprintf '\\000BEA01\\001' | dd of=\"$last\" bs=1 seek=32768 conv=notrunc 2>/dev/null\nprintf '\\000NSR03\\001' | dd of=\"$last\" bs=1 seek=34816 conv=notrunc 2>/dev/null\nprintf '\\000TEA01\\001' | dd of=\"$last\" bs=1 seek=36864 conv=notrunc 2>/dev/null\nexit 0\n",
            log.display(),
            log.display()
        );
        let tool_path = write_stub(scratch.path(), "mkudffs", &body);
        for (block, token) in [(BlockSize::Bytes512, "512"), (BlockSize::Bytes2048, "2048")] {
            // Each target starts as zeroes so only the stub's writes can
            // make the read-back verify.
            let target = scratch.path().join(format!("volume-{token}.bin"));
            std::fs::write(&target, vec![0u8; RECOGNITION_END]).expect("the zero target writes");
            let logger = Logger::new(Level::Trace);
            let options = Options::new(block);

            let verified = format_with(&target, &options, &logger, "mkudffs", &tool_path)
                .expect("the writing stub exits 0");
            assert_eq!(verified.nsr, Nsr::Nsr03, "block {token}");

            let snapshot = logger.snapshot();
            assert!(
                snapshot
                    .iter()
                    .all(|record| record.target == "udf" && record.level == Level::Info),
                "every line is logged at Info under the udf target: {snapshot:?}"
            );
            let summary = snapshot
                .last()
                .expect("the summary is logged")
                .message
                .clone();
            assert!(summary.contains("mkudffs"), "{summary}");
            assert!(summary.contains("exit status: 0"), "{summary}");
            assert!(summary.contains(token), "{summary}");
            assert!(summary.contains("no label"), "{summary}");
            assert!(summary.contains("NSR03"), "{summary}");
        }
        // Both -b values reached the tool, one argv line per run.
        let lines: Vec<String> = std::fs::read_to_string(&log)
            .expect("the stub recorded")
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("<-b><512>"), "{lines:?}");
        assert!(lines[1].contains("<-b><2048>"), "{lines:?}");
    }

    #[test]
    fn format_refuses_when_the_stub_writes_no_recognition_sequence() {
        // A stub that exits 0 without touching the target bytes: the
        // read-back must fail naming the recognition region, never Ok.
        // Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let record = scratch.path().join("args");
        let body = format!(
            "#!/bin/sh\nprintf '<%s>' \"$@\" > '{}'\nexit 0\n",
            record.display()
        );
        let tool_path = write_stub(scratch.path(), "mkudffs", &body);
        // Full-size zeroes: the read succeeds but the parse has no
        // sequence to accept.
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, vec![0u8; RECOGNITION_END]).expect("the zero target writes");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(BlockSize::Bytes512);

        let error = format_with(&target, &options, &logger, "mkudffs", &tool_path)
            .expect_err("an unwritten sequence never verifies");
        let text = error.to_string();
        assert!(matches!(error, CoreError::InvalidInput { .. }), "{text}");
        assert!(text.contains("recognition"), "{text}");
        assert!(text.contains("32768"), "{text}");
        assert!(
            record.exists(),
            "the stub ran: the failure is the read-back"
        );
    }

    #[test]
    fn format_refuses_an_nsr02_sequence_written_by_the_tool() {
        // A stub that writes NSR02, simulating --udfrev=0x0150: the run
        // must refuse with the revision-mismatch message naming both
        // identifiers. Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let record = scratch.path().join("args");
        let body = format!(
            "#!/bin/sh\nprintf '<%s>' \"$@\" > '{}'\nlast=\"\"\nfor a in \"$@\"; do last=\"$a\"; done\nprintf '\\000BEA01\\001' | dd of=\"$last\" bs=1 seek=32768 conv=notrunc 2>/dev/null\nprintf '\\000NSR02\\001' | dd of=\"$last\" bs=1 seek=34816 conv=notrunc 2>/dev/null\nprintf '\\000TEA01\\001' | dd of=\"$last\" bs=1 seek=36864 conv=notrunc 2>/dev/null\nexit 0\n",
            record.display()
        );
        let tool_path = write_stub(scratch.path(), "mkudffs", &body);
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, vec![0u8; RECOGNITION_END]).expect("the zero target writes");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(BlockSize::Bytes2048);

        let error = format_with(&target, &options, &logger, "mkudffs", &tool_path)
            .expect_err("NSR02 is a revision mismatch");
        let text = error.to_string();
        assert!(text.contains("34816"), "{text}");
        assert!(text.contains("NSR02"), "{text}");
        assert!(text.contains("NSR03"), "{text}");
        assert!(text.contains("0x0201"), "{text}");
        assert!(text.contains("mismatch"), "{text}");
    }

    #[test]
    fn format_refuses_a_bad_struct_type_written_by_the_tool() {
        // A stub that writes 0x01 as the first sector's type byte: the
        // read-back must refuse naming the offset and both values.
        // Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let record = scratch.path().join("args");
        let body = format!(
            "#!/bin/sh\nprintf '<%s>' \"$@\" > '{}'\nlast=\"\"\nfor a in \"$@\"; do last=\"$a\"; done\nprintf '\\001BEA01\\001' | dd of=\"$last\" bs=1 seek=32768 conv=notrunc 2>/dev/null\nprintf '\\000NSR03\\001' | dd of=\"$last\" bs=1 seek=34816 conv=notrunc 2>/dev/null\nprintf '\\000TEA01\\001' | dd of=\"$last\" bs=1 seek=36864 conv=notrunc 2>/dev/null\nexit 0\n",
            record.display()
        );
        let tool_path = write_stub(scratch.path(), "mkudffs", &body);
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, vec![0u8; RECOGNITION_END]).expect("the zero target writes");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(BlockSize::Bytes512);

        let error = format_with(&target, &options, &logger, "mkudffs", &tool_path)
            .expect_err("0x01 is not the struct type");
        let text = error.to_string();
        assert!(text.contains("32768"), "{text}");
        assert!(text.contains("0x01"), "{text}");
        assert!(text.contains("0x00"), "{text}");
    }

    #[test]
    fn format_accepts_the_alias_and_prefers_the_canonical_tool() {
        // The alias alone probes, the canonical name wins when both
        // exist, and a format run through the alias path verifies.
        // Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let banner = "#!/bin/sh\necho 'mkudffs from udftools 9.9' >&2\nexit 1\n";
        write_stub(scratch.path(), "mkfs.udf", banner);
        let (alias, alias_path) =
            find_tool_in(&probe_dirs(scratch.path())).expect("the alias probes");
        assert_eq!(alias, "mkfs.udf");
        assert!(alias_path.ends_with("mkfs.udf"));
        write_stub(scratch.path(), "mkudffs", banner);
        let (canonical, _) = find_tool_in(&probe_dirs(scratch.path())).expect("both stubs probe");
        assert_eq!(canonical, "mkudffs");

        // The alias path itself formats: a plain exit-0 stub under the
        // alias name verifies against a synthetic target.
        let fmt_scratch = tempfile::tempdir().expect("a scratch dir");
        let fmt_stub = write_stub(fmt_scratch.path(), "mkfs.udf", "#!/bin/sh\nexit 0\n");
        let target = write_target(fmt_scratch.path(), "volume.bin", &synthetic_region("NSR03"));
        let logger = Logger::new(Level::Trace);
        let options = Options::new(BlockSize::Bytes512);
        let verified = format_with(&target, &options, &logger, "mkfs.udf", &fmt_stub)
            .expect("the alias tool path formats");
        assert_eq!(verified.nsr, Nsr::Nsr03);
    }

    #[test]
    fn probe_skips_a_non_executable_mkudffs() {
        // A plain file without the execute bit is skipped: the probe
        // reports the package hint, never a spawn error. Stub only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        std::fs::write(scratch.path().join("mkudffs"), "#!/bin/sh\nexit 1\n")
            .expect("the non-executable file writes");
        let error =
            find_tool_in(&probe_dirs(scratch.path())).expect_err("a non-executable is skipped");
        assert!(matches!(error, CoreError::InvalidInput { .. }), "{error}");
        assert_eq!(
            error.to_string(),
            format!("invalid input: {MISSING_TOOL_HINT}"),
            "the missing-tool hint comes back"
        );
    }

    #[test]
    fn format_retries_a_busy_executable_until_it_executes() {
        // Holding the stub open for writing fails the first exec with
        // ETXTBSY; the releaser drops inside the retry budget so the run
        // still completes. Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(scratch.path(), "mkudffs", "#!/bin/sh\nexit 0\n");
        let target = write_target(scratch.path(), "volume.bin", &synthetic_region("NSR03"));
        let logger = Logger::new(Level::Trace);
        let options = Options::new(BlockSize::Bytes512);

        let held = std::fs::OpenOptions::new()
            .write(true)
            .open(&tool_path)
            .expect("the write descriptor holds");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            drop(held);
        });
        let verified = format_with(&target, &options, &logger, "mkudffs", &tool_path)
            .expect("the retry executes");
        assert_eq!(verified.nsr, Nsr::Nsr03);
        assert!(releaser.join().is_ok());
    }

    #[test]
    fn format_reports_a_spawn_error_naming_the_candidate() {
        // A directory in place of the tool file fails the spawn with
        // PermissionDenied: the run reports house io naming the path,
        // never the package hint. No stub runs here.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_dir = scratch.path().join("tool-dir");
        std::fs::create_dir(&tool_dir).expect("the tool directory creates");
        let target = write_target(scratch.path(), "volume.bin", &synthetic_region("NSR03"));
        let logger = Logger::new(Level::Trace);
        let options = Options::new(BlockSize::Bytes512);

        let error = format_with(&target, &options, &logger, "mkudffs", &tool_dir)
            .expect_err("a directory never spawns");
        let text = error.to_string();
        assert!(matches!(error, CoreError::Io { .. }), "{text}");
        assert!(text.contains(&tool_dir.display().to_string()), "{text}");
        assert!(!text.contains(MISSING_TOOL_HINT), "{text}");
        assert!(!text.contains("udftools"), "{text}");
        let CoreError::Io { source, .. } = &error else {
            panic!("the error is the house io variant: {text}")
        };
        assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn format_refuses_a_missing_target_before_any_probe_or_spawn() {
        // The stub is discoverable through the injected dir, yet a
        // missing target never invokes it: no record file appears and
        // the refusal names the target. The public entry refuses the
        // same way before any probe runs.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let record = scratch.path().join("args");
        // The stub answers the banner probe with no args and records a
        // format run otherwise, so one file serves both seams.
        let body = format!(
            "#!/bin/sh\nif [ \"$#\" = \"0\" ]; then echo 'mkudffs from udftools 9.9' >&2\nexit 1\nfi\nprintf '<%s>' \"$@\" > '{}'\nexit 0\n",
            record.display()
        );
        let tool_path = write_stub(scratch.path(), "mkudffs", &body);
        let (name, _) =
            find_tool_in(&probe_dirs(scratch.path())).expect("the stub is discoverable");
        assert_eq!(name, "mkudffs");
        let target = scratch.path().join("absent.bin");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(BlockSize::Bytes512);

        let error = format_with(&target, &options, &logger, "mkudffs", &tool_path)
            .expect_err("a missing target refuses before spawning");
        let text = error.to_string();
        assert!(text.contains("does not exist"), "{text}");
        assert!(text.contains("absent.bin"), "{text}");
        assert!(
            !record.exists(),
            "the stub never ran: the refusal precedes every tool invocation"
        );

        let error = format(&target, &options, &logger).expect_err("format refuses before probing");
        let text = error.to_string();
        assert!(text.contains("does not exist"), "{text}");
        assert!(text.contains("absent.bin"), "{text}");
    }

    #[test]
    fn format_passes_a_126_byte_label_with_spaces_and_non_ascii_byte_for_byte() {
        // A 126-byte label with spaces and one non-ASCII char reaches
        // the tool byte-for-byte while the summary echoes the sanitised
        // shape. Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let record = scratch.path().join("args");
        let body = format!(
            "#!/bin/sh\nprintf '<%s>' \"$@\" > '{}'\nexit 0\n",
            record.display()
        );
        let tool_path = write_stub(scratch.path(), "mkudffs", &body);
        let target = write_target(scratch.path(), "volume.bin", &synthetic_region("NSR03"));
        let logger = Logger::new(Level::Trace);
        // 12-byte prefix with spaces and one 2-byte char, plus 114
        // ASCII bytes: exactly the 126-byte ceiling.
        let label = format!("MY LABEL \u{e9} {}", "X".repeat(114));
        assert_eq!(label.len(), LABEL_BYTES_MAX, "the label fills the ceiling");
        assert!(label.contains(' '), "the label carries spaces");
        assert!(
            label.contains('\u{e9}'),
            "the label carries a non-ASCII char"
        );
        let options = Options::new(BlockSize::Bytes512)
            .with_label(label.clone())
            .expect("126 bytes fit the label");

        let verified = format_with(&target, &options, &logger, "mkudffs", &tool_path)
            .expect("the stub exits 0");
        assert_eq!(verified.nsr, Nsr::Nsr03);

        let recorded = std::fs::read_to_string(&record).expect("the stub recorded");
        let expected = format!(
            "<--utf8><--media-type=hd><--udfrev=0x0201><-b><512><-l><{label}><{}>",
            target.display()
        );
        assert_eq!(
            recorded, expected,
            "the label reached the tool byte-for-byte"
        );

        let summary = logger
            .snapshot()
            .last()
            .expect("the summary is logged")
            .message
            .clone();
        let sanitised = device_text(&label);
        assert!(
            summary.contains(&format!("label `{sanitised}`")),
            "{summary}"
        );
        assert!(summary.is_ascii(), "the summary echoes sanely: {summary}");
        assert!(summary.contains("NSR03"), "{summary}");
    }
}
