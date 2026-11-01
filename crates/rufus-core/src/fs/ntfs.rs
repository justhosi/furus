//! NTFS integration: drive the external `mkntfs` tool, then verify the VBR
//! and the volume-name record (S11).
//!
//! PLAN lines 661-679 mandate NTFS volumes that Windows and the UEFI:NTFS
//! driver accept, built by shelling out to
//! `mkntfs -f -L <label> -c <cluster>` under PLAN decision A4, which
//! carries some filesystems through an external-tool formatter (the ext2
//! and UDF formatters ride on the same decision), since a pure-Rust NTFS
//! writer is a multi-year project. There is no native writer here and no
//! dependency on `rufus-linux` / `rufus-helper`: the tool path arrives as
//! a target path, the tool runs as a bounded capture, and the only bytes
//! this module parses are the 512 VBR bytes and the `$MFT` record 3
//! volume-name attribute, read back from the target.
//!
//! The S21 post-format hook for the NTFS VBR fix (PLAN lines 948-949) is
//! explicitly deferred — this module ships no hook code, only this note
//! that the hook has nowhere to live until S21 re-verifies the problem on
//! Linux.
//!
//! Test discipline: the real NTFS toolchain is absent on this host, so
//! every test below drives `#!/bin/sh` stubs or synthetic VBRs / `$MFT`
//! records and claims nothing about real `mkntfs` output; the layout the
//! synthetic fixtures pin is the NTFS on-disk format, not tool
//! behaviour.

use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::exfat::get_u16;
use crate::fs::exfat::get_u32;
use crate::fs::exfat::get_u64;
use crate::fs::exfat::put_u16;
use crate::fs::tool;
use crate::log::Level;
use crate::log::Logger;
use crate::text::device_text;

/// Tool names in probe order: `mkntfs` first, then its `mkfs.ntfs` alias.
const TOOL_NAMES: [&str; 2] = ["mkntfs", "mkfs.ntfs"];

/// Smallest cluster size the options accept, in bytes.
const MIN_CLUSTER_BYTES: u32 = 512;

/// Largest cluster size the options accept, in bytes.
const MAX_CLUSTER_BYTES: u32 = 65536;

/// Cluster size [`Options::new`] defaults to, in bytes.
const DEFAULT_CLUSTER_BYTES: u32 = 4096;

/// How many of the tool's trailing stderr lines a failure report carries.
const MAX_TAIL_LINES: usize = 8;

/// Smallest `$MFT` record size the VBR shaping admits, in bytes (the
/// negative-exponent encoding 0xF6 = 2^10 shapes exactly this).
const MIN_MFT_RECORD_BYTES: u32 = 1024;

/// Largest `$MFT` record size the VBR shaping admits, in bytes.
const MAX_MFT_RECORD_BYTES: u32 = 65536;

/// The `$VOLUME_NAME` on-disk attribute type: the volume label of `$MFT`
/// record 3 lives in a resident attribute of this type (the NTFS on-disk
/// format's type code).
const TYPE_VOLUME_NAME: u32 = 0x0000_0060;

/// The attributes-walk end marker: the `u32` record type field that says
/// "no further attributes" (the NTFS on-disk format's end code).
const ATTR_END_MARKER: u32 = 0xFFFF_FFFF;

/// Byte ceiling for a resident `$VOLUME_NAME` value this reader accepts;
/// a bigger value refuses outright (pinned by a synthetic test — no
/// claim about real tool output is involved).
const MAX_NAME_VALUE_BYTES: u32 = 512;

/// Refusal when no usable NTFS formatter is on `PATH`. Package split as
/// measured in tests/ntfs_format.rs: on Arch, `mkntfs`/`mkfs.ntfs` live
/// in the separate `ntfsprogs` package, while Debian/Ubuntu ship them
/// inside the `ntfs-3g` package (PLAN.md line 137's package mapping).
const MISSING_TOOL_HINT: &str =
    "no NTFS formatter found (mkntfs or mkfs.ntfs): install ntfsprogs, or ntfs-3g on Debian/Ubuntu";

/// Locate the NTFS formatter: `mkntfs`, falling back to `mkfs.ntfs`.
///
/// Each `PATH` directory is scanned by hand (existence plus the owner execute
/// bit — never a shell, never a `PATH` mutation), and the first candidate
/// whose `--version` probe exits successfully wins; a candidate whose probe
/// fails is treated as absent. The hint names the measured package split
/// (tests/ntfs_format.rs): on Arch the formatter tools live in `ntfsprogs`,
/// which Debian/Ubuntu ships inside the `ntfs-3g` package named by PLAN.md
/// line 137.
pub fn find_tool() -> Result<&'static str> {
    find_tool_in(&tool::path_dirs()).map(|(name, _)| name)
}

/// [`find_tool`] over an explicit directory list, so tests can point the
/// probe at scratch directories without touching the process environment
/// (`std::env::set_var` is `unsafe` under this crate's edition and
/// `forbid(unsafe_code)` leaves no room for it).
fn find_tool_in(dirs: &[PathBuf]) -> Result<(&'static str, PathBuf)> {
    tool::scan_candidates(dirs, &TOOL_NAMES, "--version", missing_tool_error)
}

/// The shared refusal for an absent formatter: nothing found, nothing
/// executable, or a probe that ran and failed. Spawn failures refuse as I/O
/// errors instead, so every "the toolchain is missing" path names the same
/// package without hiding an honest spawn error.
fn missing_tool_error() -> CoreError {
    CoreError::invalid(MISSING_TOOL_HINT)
}

/// The write-side options of [`format`]: the label and the cluster size.
#[derive(Debug, Clone)]
pub struct Options {
    /// Volume label passed as `mkntfs -L`; `None` omits the flag entirely.
    pub label: Option<String>,
    /// Cluster size in bytes; see [`Options::with_cluster_bytes`].
    pub cluster_bytes: u32,
}

impl Options {
    /// Options with `label` and the default 4096-byte clusters.
    pub fn new(label: Option<String>) -> Self {
        Self {
            label,
            cluster_bytes: DEFAULT_CLUSTER_BYTES,
        }
    }

    /// Options with an explicit cluster size, refused unless it is a power
    /// of two in 512..=65536 bytes.
    pub fn with_cluster_bytes(mut self, cluster_bytes: u32) -> Result<Self> {
        if !cluster_bytes.is_power_of_two()
            || !(MIN_CLUSTER_BYTES..=MAX_CLUSTER_BYTES).contains(&cluster_bytes)
        {
            return Err(CoreError::invalid(format!(
                "cluster size {cluster_bytes} is not supported: \
                 cluster size must be a power of two from {MIN_CLUSTER_BYTES} \
                 to {MAX_CLUSTER_BYTES} bytes"
            )));
        }
        self.cluster_bytes = cluster_bytes;
        Ok(self)
    }
}

/// The verified NTFS VBR fields [`format`] reads back from the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boot {
    /// Bytes per sector from VBR offset 11: 512 or 4096.
    pub bytes_per_sector: u32,
    /// Cluster size in bytes (sectors-per-cluster times bytes-per-sector).
    pub cluster_bytes: u32,
    /// The volume length in bytes the VBR itself declares: the `u64` LE
    /// total-sectors field at offset 0x28 times the parsed bytes per
    /// sector. [`volume_label`] bounds-checks the `$MFT` record 3
    /// window against this VBR-declared length and nothing else — not
    /// the target's metadata stat. Zero total sectors refuse in
    /// [`boot_sector`], and the product refusing on `u64` overflow
    /// does too.
    pub volume_bytes: u64,
    /// Volume serial from VBR offset 0x48.
    pub volume_serial: u64,
    /// First cluster of `$MFT` from the `u64` LE at VBR offset 0x30.
    /// Zero is refused by [`boot_sector`]: a VBR that names no `$MFT`
    /// leaves nothing to verify the label in.
    pub mft_start_cluster: u64,
    /// `$MFT` record size in bytes, shaped from the signed-ish `u8` at
    /// VBR offset 0x40; see [`boot_sector`] for the accepted shapes.
    pub mft_record_bytes: u32,
}

/// Verify a 512-byte NTFS volume boot record.
///
/// Checks, in order: the `NTFS    ` magic at 3..11; bytes-per-sector (`u16`
/// LE at 11) is 512 or 4096 — the only sizes the house
/// [`Volume`](crate::fs::Volume) trait admits; sectors-per-cluster (`u8`
/// at 13) is non-zero and the resulting cluster size lands in
/// 512..=65536 bytes; the total sector count (`u64` LE at 0x28) is
/// non-zero — the VBR's own declaration is the only volume length the
/// label read checks against — and its product with the parsed sector
/// size pre-computes into [`Boot::volume_bytes`], refused on `u64`
/// overflow; the `$MFT` start cluster (`u64` LE at 0x30) is
/// non-zero; the `0x55 0xAA` signature at 510..512. The signed-ish `u8`
/// at 0x40 shapes the `$MFT` record size per the NTFS on-disk format,
/// and the shape is refused when it does not produce a power of two in
/// 1024..=65536 bytes: bit 0x80 clear — a positive cluster count whose
/// product with the parsed cluster size must be such a power of two;
/// bit 0x80 set — a byte-size exponent, record bytes 2^(256 - byte),
/// accepted exactly for the exponents inside that window. Returns the
/// parsed sector size, cluster size, declared volume length, `$MFT`
/// start cluster and shaped `$MFT` record size, and the `u64` LE
/// volume serial at 0x48.
///
/// The field reads reuse the exFAT side's checked getters — one helper set
/// for the whole `fs` tree, no second implementation to drift. The record
/// shaping is this reader's reading of the on-disk format; real `mkntfs`
/// behaviour is not claimed (the toolchain is absent on this host, per the
/// module header's test discipline).
pub fn boot_sector(vbr: &[u8; 512]) -> Result<Boot> {
    if vbr.get(3..11) != Some(b"NTFS    ".as_slice()) {
        return Err(CoreError::invalid(
            "not an NTFS volume: bytes 3..11 do not read `NTFS    `",
        ));
    }
    let bytes_per_sector = get_u16(vbr, 11).ok_or_else(|| {
        CoreError::invalid("NTFS VBR ends before the bytes-per-sector field at offset 11")
    })?;
    if !matches!(bytes_per_sector, 512 | 4096) {
        return Err(CoreError::invalid(format!(
            "NTFS bytes per sector {bytes_per_sector} is not supported: \
             only 512 and 4096 are allowed"
        )));
    }
    let sectors_per_cluster = vbr.get(13).copied().ok_or_else(|| {
        CoreError::invalid("NTFS VBR ends before the sectors-per-cluster field at offset 13")
    })?;
    if sectors_per_cluster == 0 {
        return Err(CoreError::invalid(
            "NTFS sectors per cluster is zero: the VBR names no cluster size",
        ));
    }
    // With bytes-per-sector restricted to 512/4096 above, every cluster
    // size in 512..=65536 is a positive sectors-per-cluster ratio
    // (1..=128 at 512 bytes, 1..=16 at 4096 bytes), so the range check
    // below doubles as the encoding check — a zero ratio is still refused
    // explicitly above, and no claim is made here about which cluster
    // sizes real `mkntfs` runs emit.
    let cluster_bytes = u32::from(sectors_per_cluster)
        .checked_mul(u32::from(bytes_per_sector))
        .ok_or_else(|| CoreError::invalid("NTFS cluster size overflows a u32"))?;
    if !(MIN_CLUSTER_BYTES..=MAX_CLUSTER_BYTES).contains(&cluster_bytes) {
        return Err(CoreError::invalid(format!(
            "NTFS cluster size {cluster_bytes} is out of range: \
             cluster size must be from {MIN_CLUSTER_BYTES} to {MAX_CLUSTER_BYTES} bytes"
        )));
    }
    let total_sectors = get_u64(vbr, 0x28).ok_or_else(|| {
        CoreError::invalid("NTFS VBR ends before the total sectors at offset 0x28")
    })?;
    if total_sectors == 0 {
        return Err(CoreError::invalid(
            "NTFS total sectors is zero: the VBR declares an empty volume",
        ));
    }
    let volume_bytes = total_sectors
        .checked_mul(u64::from(bytes_per_sector))
        .ok_or_else(|| {
            CoreError::invalid("NTFS total sectors times the sector size overflows a u64")
        })?;
    let mft_start_cluster = get_u64(vbr, 0x30).ok_or_else(|| {
        CoreError::invalid("NTFS VBR ends before the $MFT start cluster at offset 0x30")
    })?;
    if mft_start_cluster == 0 {
        return Err(CoreError::invalid(
            "NTFS $MFT start cluster is zero: the VBR names no record area",
        ));
    }
    let mft_record_bytes = shape_mft_record_bytes(vbr, cluster_bytes)?;
    let signature: &[u8] = &[0x55, 0xAA];
    if vbr.get(510..512) != Some(signature) {
        return Err(CoreError::invalid(
            "not an NTFS boot sector: bytes 510..511 are not 0x55 0xAA",
        ));
    }
    let volume_serial = get_u64(vbr, 0x48).ok_or_else(|| {
        CoreError::invalid("NTFS VBR ends before the volume serial at offset 0x48")
    })?;
    Ok(Boot {
        bytes_per_sector: u32::from(bytes_per_sector),
        cluster_bytes,
        volume_bytes,
        volume_serial,
        mft_start_cluster,
        mft_record_bytes,
    })
}

/// Shape the `$MFT` record size in bytes from VBR offset 0x40.
///
/// Per the NTFS on-disk format, the byte encodes the record size either
/// positively — a cluster count, so the size is `byte * cluster_bytes`
/// (no `u32` overflow: the multiplier caps at 127 and the parsed cluster
/// at 65536) — or as the negative half 0x80..=0xFF, whose record size is
/// `2^(256 - byte)` bytes. Both encodings must land on a power of two
/// within [`MIN_MFT_RECORD_BYTES`]..=[`MAX_MFT_RECORD_BYTES`] bytes;
/// every other shape (a zero count, a size below the floor, an exponent
/// whose power outruns the ceiling — 0x86 would name 2^122 bytes) refuses.
fn shape_mft_record_bytes(vbr: &[u8; 512], cluster_bytes: u32) -> Result<u32> {
    let clusters_per_record = vbr.get(0x40).copied().ok_or_else(|| {
        CoreError::invalid("NTFS VBR ends before the clusters-per-$MFT-record field at offset 0x40")
    })?;
    if clusters_per_record & 0x80 == 0 {
        if clusters_per_record == 0 {
            return Err(CoreError::invalid(
                "NTFS clusters-per-MFT-record is zero: the VBR names no record size",
            ));
        }
        let product = u32::from(clusters_per_record) * cluster_bytes;
        if !product.is_power_of_two()
            || !(MIN_MFT_RECORD_BYTES..=MAX_MFT_RECORD_BYTES).contains(&product)
        {
            return Err(CoreError::invalid(format!(
                "NTFS clusters-per-MFT-record {clusters_per_record} over {cluster_bytes} \
                 byte clusters gives a {product} byte $MFT record: the record must be \
                 a power of two from {MIN_MFT_RECORD_BYTES} to {MAX_MFT_RECORD_BYTES} bytes"
            )));
        }
        return Ok(product);
    }
    // Negative encoding: 256 - byte is the exponent; 0xF6 -> 2^10 = 1024.
    let exponent = u32::from(clusters_per_record ^ 0xFF) + 1;
    if !(10..=16).contains(&exponent) {
        return Err(CoreError::invalid(format!(
            "NTFS clusters-per-MFT-record 0x{clusters_per_record:02X} encodes \
             2^{exponent} bytes for the $MFT record: the encoded size must stay \
             within {MIN_MFT_RECORD_BYTES} to {MAX_MFT_RECORD_BYTES} bytes"
        )));
    }
    Ok(1u32 << exponent)
}

/// Format `target` as NTFS with the external formatter.
///
/// Runs `mkntfs -f [-L <label>] -c <cluster> <target>` (the target path is
/// always the last argument) as a bounded capture — both streams piped and
/// drained via `output()`, `LC_ALL=C` in the child environment — then reads
/// back bytes 0..512 and verifies them with [`boot_sector`], and reads the
/// volume name of `$MFT` record 3 with [`volume_label`]. Every
/// non-empty captured line (stdout then stderr, each through
/// [`device_text`]) is logged verbatim at `Info` under the `ntfs` target;
/// a failing exit becomes a refusal naming the tool, the status and the
/// last [`MAX_TAIL_LINES`] stderr lines. A label-READ failure after a
/// successful run is a hard refusal too (an unverified label means the
/// format is not trusted); it is logged at `Error` before the error is
/// returned. On success the summary is the snapshot's final line and the
/// verified boot plus label come back as an [`NtfsVolume`].
pub fn format(target: &Path, options: &Options, logger: &Logger) -> Result<NtfsVolume> {
    let (tool, tool_path) = find_tool_in(&tool::path_dirs())?;
    format_with(target, options, logger, tool, &tool_path)
}

/// The verified return of [`format`]: the boot fields and the volume
/// label read back from the formatted target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsVolume {
    /// The verified VBR fields.
    pub boot: Boot,
    /// The volume name `volume_label` decoded from `$MFT` record 3;
    /// `None` when the record carries no `$VOLUME_NAME` attribute.
    pub label: Option<String>,
}

/// [`format`] with the tool already resolved, so tests can point the run at
/// a stub by absolute path without touching the process environment.
fn format_with(
    target: &Path,
    options: &Options,
    logger: &Logger,
    tool: &str,
    tool_path: &Path,
) -> Result<NtfsVolume> {
    let mut command = Command::new(tool_path);
    command.arg("-f");
    if let Some(label) = options.label.as_deref() {
        command.arg("-L").arg(label);
    }
    command
        .arg("-c")
        .arg(options.cluster_bytes.to_string())
        .arg(target);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C");
    // Bounded capture: the tool is this slice's external mandate
    // (PLAN lines 661-679), and `output` drains both pipes so a chatty
    // tool cannot block on a full buffer.
    let output =
        tool::output_retrying(&mut command).map_err(|error| CoreError::io(tool_path, error))?;

    let stdout_lines = captured_lines(&output.stdout);
    let stderr_lines = captured_lines(&output.stderr);
    for line in stdout_lines.iter().chain(stderr_lines.iter()) {
        logger.log(Level::Info, "ntfs", line);
    }

    if !output.status.success() {
        return Err(format_failure(
            tool,
            &output.status.to_string(),
            &stderr_lines,
        ));
    }

    let boot = boot_sector(&read_vbr(target)?)?;
    let label = match volume_label(target, &boot) {
        Ok(label) => label,
        Err(err) => {
            logger.log(
                Level::Error,
                "ntfs",
                &format!("{tool} succeeded but the volume label could not be verified: {err}"),
            );
            return Err(err);
        }
    };
    match label.as_deref() {
        Some(name) => logger.log(
            Level::Info,
            "ntfs",
            &format!("verified NTFS volume label `{name}` in $MFT record 3"),
        ),
        None => logger.log(
            Level::Info,
            "ntfs",
            "the NTFS volume carries no `$VOLUME_NAME` attribute in $MFT record 3",
        ),
    };
    logger.log(
        Level::Info,
        "ntfs",
        &format!(
            "{tool} finished ({}): verified NTFS volume with {} byte sectors and {} byte clusters",
            output.status, boot.bytes_per_sector, boot.cluster_bytes,
        ),
    );
    Ok(NtfsVolume { boot, label })
}

/// Split captured output into sanitised, non-empty log lines.
fn captured_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(device_text)
        .filter(|line| !line.is_empty())
        .collect()
}

/// Refusal for a failing tool exit: the tool name, the status text and the
/// last [`MAX_TAIL_LINES`] stderr lines (empty when the tool said nothing).
fn format_failure(tool: &str, status: &str, stderr_lines: &[String]) -> CoreError {
    let mut tail: Vec<&str> = stderr_lines
        .iter()
        .rev()
        .take(MAX_TAIL_LINES)
        .map(String::as_str)
        .collect();
    tail.reverse();
    if tail.is_empty() {
        CoreError::invalid(format!("{tool} failed ({status}) with no error output"))
    } else {
        CoreError::invalid(format!("{tool} failed ({status}): {}", tail.join("; ")))
    }
}

/// Read bytes 0..512 of `target` — the VBR the tool is expected to have
/// written — for [`boot_sector`] verification.
fn read_vbr(target: &Path) -> Result<[u8; 512]> {
    let file = std::fs::File::open(target).map_err(|err| CoreError::io(target, err))?;
    let mut vbr = [0u8; 512];
    file.read_exact_at(&mut vbr, 0)
        .map_err(|err| CoreError::io(target, err))?;
    Ok(vbr)
}

/// Read the volume label from `$MFT` record 3 of `target`.
///
/// `boot` carries the verified VBR facts and drives the arithmetic — the
/// record lives `boot.mft_start_cluster * boot.cluster_bytes` bytes into
/// the target and record 3 at `3` records (`boot.mft_record_bytes` each)
/// past that. The record window is bounds-checked against the volume
/// length the target's own VBR declares (`Boot::volume_bytes`, the total
/// sectors at offset 0x28 times the bytes per sector) before anything is
/// read — never the target's metadata stat — and the read is one exact
/// [`FileExt::read_exact_at`] that io-fails when the actual target comes
/// up short of what its VBR declared.
///
/// Per the NTFS on-disk format, record 3 then must read `FILE` at 0..4
/// and carry the update sequence array: its `u16` LE offset sits in
/// bytes 4..6 and its entry count in 6..8 — the count must be
/// `record_bytes / 512 + 1`, the array must fit the record, and every
/// 512-byte step of the record must end in the array's first entry (the
/// running sequence number); each step's trailing bytes are then
/// patched back to the array's saved value for that step. Any mismatch
/// refuses — the only accepted shape is the format's, and a real
/// mkntfs-written volume passing this reader is slice 3's container-run
/// guarantee, not a claim made here.
///
/// The attribute walk starts at the `u16` LE offset in record bytes
/// 20..22 and is bounded by the `u32` LE bytes-in-use field at 24..28 —
/// more bytes in use than the record holds refuses, and reaching the
/// in-use end without the 0xFFFF_FFFF end marker refuses, each naming
/// the walker position and the markerless bound. Each attribute is a
/// `u32` LE type at 0..4 and a `u32` LE length at 4..8; zero lengths and
/// attributes overstaying the in-use bytes refuse, and the walk hands
/// the first `$VOLUME_NAME` attribute ([`TYPE_VOLUME_NAME`]) to
/// [`volume_name_value`]. No `$VOLUME_NAME` before the end marker is
/// `Ok(None)`.
pub fn volume_label(target: &Path, boot: &Boot) -> Result<Option<String>> {
    let file = std::fs::File::open(target).map_err(|err| CoreError::io(target, err))?;

    let record_bytes = u64::from(boot.mft_record_bytes);
    let mft_offset = boot
        .mft_start_cluster
        .checked_mul(u64::from(boot.cluster_bytes))
        .ok_or_else(|| {
            CoreError::invalid(
                "the NTFS $MFT byte offset overflows: refusing to read the volume label",
            )
        })?;
    let record_at = mft_offset.checked_add(3 * record_bytes).ok_or_else(|| {
        CoreError::invalid(
            "the NTFS $MFT record 3 byte offset overflows: refusing to read the volume label",
        )
    })?;
    let record_end = record_at.checked_add(record_bytes).ok_or_else(|| {
        CoreError::invalid(
            "the NTFS $MFT record 3 byte offset overflows: refusing to read the volume label",
        )
    })?;
    if record_end > boot.volume_bytes {
        return Err(CoreError::invalid(format!(
            "the NTFS $MFT record 3 at byte {record_at} needs bytes up to \
             {record_end} but the volume the VBR declares holds only \
             {} bytes",
            boot.volume_bytes
        )));
    }

    let mut record = vec![0u8; boot.mft_record_bytes as usize];
    file.read_exact_at(&mut record, record_at)
        .map_err(|err| CoreError::io(target, err))?;
    let record_len = record.len();
    if record.get(0..4) != Some(b"FILE".as_slice()) {
        return Err(CoreError::invalid(format!(
            "not an NTFS $MFT record: bytes 0..4 of the record at byte \
             {record_at} do not read `FILE`"
        )));
    }

    let usn_offset = usize::from(get_u16(&record, 4).ok_or_else(|| {
        CoreError::invalid(
            "the NTFS $MFT record is too small for the fixup array offset in bytes 4..6",
        )
    })?);
    let usn_count = get_u16(&record, 6).ok_or_else(|| {
        CoreError::invalid(
            "the NTFS $MFT record is too small for the fixup entry count in bytes 6..8",
        )
    })?;
    // Update sequence fixup, pinned by the synthetic tests: the count
    // counts the sequence stored at usn_offset plus one saved value per
    // 512-byte step of the record. Fixup blocks are 512-byte units per
    // the update-sequence layout (ntfs-3g fixes NTFS_BLOCK_SIZE at 512);
    // a real 4Kn volume is settled by slice 3's container run — failing
    // closed here is intentional.
    let expected_count = boot.mft_record_bytes / 512 + 1;
    if u32::from(usn_count) != expected_count {
        return Err(CoreError::invalid(format!(
            "the NTFS $MFT record at byte {record_at} declares {usn_count} fixup \
             entries but its {record_len} byte record implies {expected_count}"
        )));
    }
    let array_end = usn_offset + 2 * usize::from(usn_count);
    if array_end > record_len {
        return Err(CoreError::invalid(format!(
            "the NTFS fixup array at record offset {usn_offset} ({usn_count} \
             entries) does not fit the {record_len} byte $MFT record at byte {record_at}"
        )));
    }
    // Per the update-sequence layout, the array must finish before the
    // first block's protected tail at record offset 510..512: those two
    // bytes are the tracked sequence slot, never array content.
    if array_end > 510 {
        return Err(CoreError::invalid(format!(
            "the NTFS fixup array at record offset {usn_offset} ({usn_count} \
             entries) ends at record offset {array_end} but the first protected \
             block tail starts at 510"
        )));
    }
    let signature = get_u16(&record, usn_offset).ok_or_else(|| {
        CoreError::invalid(format!(
            "the NTFS fixup array at record offset {usn_offset} of the $MFT record \
             at byte {record_at} does not fit its {record_len} byte record"
        ))
    })?;
    // The stored record ends every 512-byte step with the sequence value
    // (the array's first entry); the remaining entries hold the saved
    // originals, patched back here. Index i in the array therefore drives
    // step i - 1 of the record: entry 1 restores step 0, entry 2 step 1,
    // and so on.
    for step in 0..usize::from(usn_count) - 1 {
        let trailing_at = (step + 1) * 512 - 2;
        let trailing = get_u16(&record, trailing_at).ok_or_else(|| {
            CoreError::invalid(format!(
                "the NTFS $MFT record at byte {record_at} ends before its fixup \
                 block at record offset {trailing_at}"
            ))
        })?;
        if trailing != signature {
            return Err(CoreError::invalid(format!(
                "the NTFS $MFT record at byte {record_at} ends its 512 byte block \
                 at record offset {trailing_at} with 0x{trailing:04X} but the fixup \
                 sequence is 0x{signature:04X}"
            )));
        }
        // Saved entries sit inside the fit-checked array window above.
        let saved = get_u16(&record, usn_offset + 2 * (step + 1)).ok_or_else(|| {
            CoreError::invalid(format!(
                "the NTFS fixup array at record offset {usn_offset} of the $MFT \
                 record at byte {record_at} does not fit its {record_len} byte record"
            ))
        })?;
        put_u16(&mut record, trailing_at, saved)?;
    }

    let attrs_offset = get_u16(&record, 20).map(usize::from).ok_or_else(|| {
        CoreError::invalid(
            "the NTFS $MFT record is too small for the attributes offset in bytes 20..22",
        )
    })?;
    let bytes_in_use = get_u32(&record, 24)
        .map(|bytes| bytes as usize)
        .ok_or_else(|| {
            CoreError::invalid(
                "the NTFS $MFT record is too small for the bytes-in-use field in bytes 24..28",
            )
        })?;
    if bytes_in_use > record_len {
        return Err(CoreError::invalid(format!(
            "the NTFS $MFT record at byte {record_at} declares {bytes_in_use} bytes \
             in use but holds {record_len} bytes"
        )));
    }
    let mut at = attrs_offset;
    loop {
        // The walk is bounded by the declared in-use bytes: a walker
        // position past them means no end marker ever appeared, so the
        // shape is not the format's.
        if at >= bytes_in_use {
            return Err(CoreError::invalid(format!(
                "the NTFS attribute walk of the $MFT record at byte {record_at} reaches \
                 record offset {at} without an attribute end marker inside its \
                 {bytes_in_use} bytes in use"
            )));
        }
        let record_type =
            get_u32(&record, at).ok_or_else(|| walk_refusal(record_at, at, record_len))?;
        if record_type == ATTR_END_MARKER {
            break;
        }
        let length =
            get_u32(&record, at + 4).ok_or_else(|| walk_refusal(record_at, at + 4, record_len))?;
        if length == 0 {
            return Err(CoreError::invalid(format!(
                "the NTFS attribute at record offset {at} of the $MFT record at \
                 byte {record_at} declares length 0"
            )));
        }
        let next = at
            .checked_add(length as usize)
            .filter(|&next| next <= bytes_in_use)
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "the NTFS attribute at record offset {at} of the $MFT record at \
                     byte {record_at} extends past its {bytes_in_use} bytes in use"
                ))
            })?;
        if record_type == TYPE_VOLUME_NAME {
            return volume_name_value(&record, record_at, at, length);
        }
        at = next;
    }
    Ok(None)
}

/// The walk refusal shared by the attribute readers: reading anything at
/// `at` failed because the record is over.
fn walk_refusal(record_at: u64, at: usize, record_len: usize) -> CoreError {
    CoreError::invalid(format!(
        "the NTFS attribute walk of the $MFT record at byte {record_at} \
         reaches record offset {at} but the record holds {record_len} bytes"
    ))
}

/// Deliver the value window of the resident `$VOLUME_NAME` attribute at
/// record offset `at` (whose own length `attr_length` the walk verified
/// into the in-use bytes) as the label: non-resident refuses; the value
/// is a `u32` LE length at header bytes 16..20 and a `u16` LE offset at
/// 20..22 whose value offset is relative to the start of the attribute
/// record (per the ntfs-3g / linux-ntfs on-disk layout: unnamed resident
/// headers keep the value offset at 0x18), so the label bytes live at
/// record offset `at + value_offset`. The window must start past the
/// resident header — 24 attribute bytes unnamed, past a named
/// attribute's name bytes (`name offset + 2 * name length`,
/// attribute-relative) otherwise — and stay inside both the attribute's
/// own window and the record window, fail-closed; beside that it must be
/// even-sized and at most [`MAX_NAME_VALUE_BYTES`] bytes, and a zero
/// length is the label-less volume. The bytes decode as UTF-16LE units
/// through `String::from_utf16_lossy` — lossy on purpose: stray units
/// surface in the label instead of failing a format run this module
/// already verified otherwise, and nothing is trimmed (zero-padded
/// values keep their NUL units; a test pins that).
fn volume_name_value(
    record: &[u8],
    record_at: u64,
    at: usize,
    attr_length: u32,
) -> Result<Option<String>> {
    let record_len = record.len();
    let nonresident = record.get(at + 8).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "the $VOLUME_NAME attribute at record offset {at} of the $MFT record at \
             byte {record_at} lacks its resident flag inside the {record_len} byte record"
        ))
    })?;
    if nonresident != 0 {
        return Err(CoreError::invalid(format!(
            "the $VOLUME_NAME attribute at record offset {at} of the $MFT record at \
             byte {record_at} is non-resident: only a resident name is read"
        )));
    }
    let value_length =
        get_u32(record, at + 16).ok_or_else(|| walk_refusal(record_at, at + 16, record_len))?;
    let value_offset = get_u16(record, at + 20)
        .map(usize::from)
        .ok_or_else(|| walk_refusal(record_at, at + 20, record_len))?;
    if value_length == 0 {
        return Ok(None);
    }
    // Resident floor: an unnamed resident header occupies 24 attribute
    // bytes; a named attribute's value starts past its name bytes (the
    // name offset is attribute-relative too).
    let name_length = record.get(at + 9).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "the $VOLUME_NAME attribute at record offset {at} of the $MFT record at \
             byte {record_at} lacks its name length inside the {record_len} byte record"
        ))
    })?;
    let floor = if name_length == 0 {
        24
    } else {
        let name_offset = get_u16(record, at + 10).map(usize::from).ok_or_else(|| {
            CoreError::invalid(format!(
                "the $VOLUME_NAME attribute at record offset {at} of the $MFT record at \
                     byte {record_at} lacks its name offset inside the {record_len} byte record"
            ))
        })?;
        name_offset
            .checked_add(2 * usize::from(name_length))
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "the $VOLUME_NAME attribute at record offset {at} of the $MFT record at \
                     byte {record_at} overflows its {name_length} unit name floor"
                ))
            })?
    };
    if value_offset < floor {
        return Err(CoreError::invalid(format!(
            "the $VOLUME_NAME attribute at record offset {at} of the $MFT record at \
             byte {record_at} packs its value offset {value_offset} inside the \
             resident header floor at {floor} attribute bytes"
        )));
    }
    if value_length > MAX_NAME_VALUE_BYTES {
        return Err(CoreError::invalid(format!(
            "the $VOLUME_NAME attribute at record offset {at} of the $MFT record at \
             byte {record_at} declares a {value_length} byte value: over \
             {MAX_NAME_VALUE_BYTES} bytes is refused"
        )));
    }
    // The value offset is relative to the start of the attribute record:
    // absolute label bytes sit at `at + value_offset`, bounded by both
    // the attribute's own window and the record window.
    let value_at = at.checked_add(value_offset).ok_or_else(|| {
        CoreError::invalid(format!(
            "the $VOLUME_NAME value at record offset {at}+{value_offset} does not fit \
             the {record_len} byte $MFT record at byte {record_at}"
        ))
    })?;
    let value_end = value_at.checked_add(value_length as usize).ok_or_else(|| {
        CoreError::invalid(format!(
            "the $VOLUME_NAME value bytes from record offset {value_at} do not fit \
                 the {record_len} byte $MFT record at byte {record_at}"
        ))
    })?;
    let attr_end = at.checked_add(attr_length as usize).ok_or_else(|| {
        CoreError::invalid(format!(
            "the $VOLUME_NAME attribute window at record offset {at} does not fit \
             the {record_len} byte $MFT record at byte {record_at}"
        ))
    })?;
    if value_end > attr_end {
        return Err(CoreError::invalid(format!(
            "the $VOLUME_NAME value bytes {value_at}..{value_end} overrun the attribute \
             window {at}..{attr_end} of the $MFT record at byte {record_at}"
        )));
    }
    if value_end > record_len {
        return Err(CoreError::invalid(format!(
            "the $VOLUME_NAME value bytes {value_at}..{value_end} do not fit the \
             {record_len} byte $MFT record at byte {record_at}"
        )));
    }
    if value_length % 2 == 1 {
        return Err(CoreError::invalid(format!(
            "the $VOLUME_NAME attribute at record offset {at} of the $MFT record at \
             byte {record_at} declares an odd {value_length} byte value: UTF-16 labels \
             are even-sized"
        )));
    }
    let mut units = Vec::with_capacity(value_length as usize / 2);
    for step in 0..value_length / 2 {
        // Attribute-relative: absolute record offsets start at value_at.
        let unit_at = value_at + 2 * step as usize;
        // The window above bounds-checked the units into the record.
        let unit =
            get_u16(record, unit_at).ok_or_else(|| walk_refusal(record_at, unit_at, record_len))?;
        units.push(unit);
    }
    Ok(Some(String::from_utf16_lossy(&units)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A fixed serial baked into every synthetic VBR, so the round-trip
    /// pins the exact `u64` LE field rather than "some serial".
    const SYNTHETIC_SERIAL: u64 = 0x0123_4567_89AB_CDEF;

    /// The `$MFT` start cluster every synthetic VBR names at 0x30: 8
    /// clusters in, a non-zero layout the VBR checks accept.
    const SYNTHETIC_MFT_CLUSTER: u64 = 8;

    /// The synthetic `$MFT` record size: 1024 bytes, encoded at 0x40 as
    /// the on-disk format's negative byte-exponent 0xF6 = 2^10.
    const SYNTHETIC_RECORD_BYTES: u32 = 1024;

    /// The byte length every [`write_target`] image gets: `$MFT` start
    /// cluster times the synthetic 4096-byte clusters, plus four
    /// records (records 0..3 with the label record last). Every
    /// synthetic VBR's 0x28 total sectors divide this length by the
    /// VBR's own sector size, so the declared volume length matches
    /// the image length exactly.
    const SYNTHETIC_TARGET_BYTES: u64 =
        SYNTHETIC_MFT_CLUSTER * 4096 + 4 * (SYNTHETIC_RECORD_BYTES as u64);

    /// Where the fixup array sits in the synthetic records — the
    /// canonical position (VBR-independent) of the on-disk layout.
    const SYNTHETIC_USA_OFFSET: u16 = 48;

    /// The fixup sequence value the synthetic records store and the
    /// trailing u16 slots of every 512-byte step must match.
    const SYNTHETIC_USA_VALUE: u16 = 1;

    /// Stored fixup saved values (array entries 1..2): distinct from
    /// [`SYNTHETIC_USA_VALUE`], so a missing restore is observable.
    const SYNTHETIC_USA_SAVED: [u16; 2] = [0xAAAA, 0xBBBB];

    /// "RUFUS NTFS" as the UTF-16LE units the synthetic volume-name
    /// attribute carries by default.
    const RUFUS_NTFS_UNITS: [u16; 10] = [
        0x0052, 0x0055, 0x0046, 0x0055, 0x0053, 0x0020, 0x004E, 0x0054, 0x0046, 0x0053,
    ];

    /// Build a synthetic 512-byte VBR for (`bytes_per_sector`,
    /// `cluster_bytes`). Stub/synthetic only: pins the layout this module
    /// parses, claims nothing about real `mkntfs` output. The `$MFT`
    /// fields at 0x30/0x40 come from the [`SYNTHETIC_MFT_CLUSTER`] /
    /// [`SYNTHETIC_RECORD_BYTES`] defaults above, and the 0x28 total
    /// sectors divide [`SYNTHETIC_TARGET_BYTES`] by this VBR's own
    /// sector size, so `boot_sector`'s non-zero total-sector check
    /// accepts and the declared volume length is exact.
    fn synthetic_vbr(bytes_per_sector: u16, cluster_bytes: u32) -> [u8; 512] {
        let mut vbr = [0u8; 512];
        vbr[3..11].copy_from_slice(b"NTFS    ");
        vbr[11..13].copy_from_slice(&bytes_per_sector.to_le_bytes());
        let ratio = cluster_bytes / u32::from(bytes_per_sector);
        vbr[13] = ratio as u8;
        // Offset 0x28: the u64 LE total sectors the VBR declares.
        vbr[0x28..0x30]
            .copy_from_slice(&(SYNTHETIC_TARGET_BYTES / u64::from(bytes_per_sector)).to_le_bytes());
        vbr[0x30..0x38].copy_from_slice(&SYNTHETIC_MFT_CLUSTER.to_le_bytes());
        // 0xF6 = -10: the negative byte-exponent encoding of a 1024-byte
        // $MFT record (per the on-disk format; synthetic, not a tool
        // claim).
        vbr[0x40] = 0xF6;
        vbr[0x48..0x50].copy_from_slice(&SYNTHETIC_SERIAL.to_le_bytes());
        vbr[510] = 0x55;
        vbr[511] = 0xAA;
        vbr
    }

    /// The [`Boot`] every synthetic target parses into: 512-byte sectors,
    /// 4096-byte clusters, `$MFT` at cluster 8, 1024-byte records.
    fn test_boot() -> Boot {
        boot_sector(&synthetic_vbr(512, 4096)).expect("the synthetic VBR parses")
    }

    /// Build a synthetic 1024-byte `$MFT` record 3: `FILE` magic, the
    /// canonical fixup array (sequence plus [`SYNTHETIC_USA_SAVED`]
    /// saved values, both trailing slots storing the sequence value the
    /// reader expects), and one resident `$VOLUME_NAME` attribute
    /// carrying `label` — none when `label` is empty, only the 0xFFFF_FFFF
    /// end marker then. Stub/synthetic only: pins the layout this module
    /// reads, claims nothing about real `mkntfs` output.
    fn synthetic_record(label: &[u16]) -> Vec<u8> {
        let mut record = vec![0u8; SYNTHETIC_RECORD_BYTES as usize];
        record[0..4].copy_from_slice(b"FILE");
        record[4..6].copy_from_slice(&SYNTHETIC_USA_OFFSET.to_le_bytes());
        // count = record/512 + 1 = 3: the sequence value and one saved
        // value per 512-byte step.
        record[6..8].copy_from_slice(&3u16.to_le_bytes());
        record[20..22].copy_from_slice(&56u16.to_le_bytes());
        record[48..50].copy_from_slice(&SYNTHETIC_USA_VALUE.to_le_bytes());
        for (i, saved) in SYNTHETIC_USA_SAVED.iter().enumerate() {
            record[50 + 2 * i..52 + 2 * i].copy_from_slice(&saved.to_le_bytes());
        }
        // The stored record ends both 512-byte steps with the sequence
        // value; the reader patches the saved values back in place.
        record[510..512].copy_from_slice(&SYNTHETIC_USA_VALUE.to_le_bytes());
        record[1022..1024].copy_from_slice(&SYNTHETIC_USA_VALUE.to_le_bytes());
        if label.is_empty() {
            record[56..60].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
            // bytes_in_use covers the end marker the walker stops at.
            record[24..28].copy_from_slice(&60u32.to_le_bytes());
            return record;
        }
        // One resident $VOLUME_NAME attribute at 56: the unnamed resident
        // header owns the first 24 attribute bytes, and the value offset
        // field is relative to the start of the attribute record, so 0x18
        // = 24 puts the UTF-16LE value bytes at record offset 56 + 24 = 80.
        record[56..60].copy_from_slice(&TYPE_VOLUME_NAME.to_le_bytes());
        let length = 24 + label.len() * 2;
        record[60..64].copy_from_slice(&(length as u32).to_le_bytes());
        // 0 at header byte 8 = resident.
        record[64] = 0;
        record[72..76].copy_from_slice(&(label.len() as u32 * 2).to_le_bytes());
        record[76..78].copy_from_slice(&24u16.to_le_bytes());
        for (i, unit) in label.iter().enumerate() {
            record[80 + 2 * i..82 + 2 * i].copy_from_slice(&unit.to_le_bytes());
        }
        record[56 + length..60 + length].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
        // bytes_in_use covers the attributes through their end marker;
        // the walker's stop-at-marker read needs the marker in use.
        record[24..28].copy_from_slice(&((56 + length + 4) as u32).to_le_bytes());
        record
    }

    /// Write the synthetic target for [`test_boot`]: VBR at 0 and record 3
    /// at `$MFT` + 3 records, so the file is exactly long enough to hold
    /// record 3 once. Returns the path.
    fn write_target(scratch: &Path, record: &[u8]) -> PathBuf {
        let mft_offset = SYNTHETIC_MFT_CLUSTER * 4096;
        let mut image = vec![0u8; SYNTHETIC_TARGET_BYTES as usize];
        image[..512].copy_from_slice(&synthetic_vbr(512, 4096));
        let record_at = (mft_offset + 3 * u64::from(SYNTHETIC_RECORD_BYTES)) as usize;
        image[record_at..record_at + record.len()].copy_from_slice(record);
        let target = scratch.join("volume.bin");
        std::fs::write(&target, &image).expect("the synthetic target writes");
        target
    }

    /// `volume_label` over [`synthetic_record`] with `mutate` applied to
    /// the record: returns the refusal text the reader must produce.
    fn label_refusal_text(scratch: impl AsRef<Path>, mutate: impl FnOnce(&mut [u8])) -> String {
        let scratch = scratch.as_ref();
        let mut record = synthetic_record(&RUFUS_NTFS_UNITS);
        mutate(&mut record);
        let target = write_target(scratch, &record);
        volume_label(&target, &test_boot())
            .expect_err("the damaged synthetic record refuses")
            .to_string()
    }

    /// `volume_label` returning the decoded label over an explicit
    /// record (the happy path helper).
    fn label_of_record(scratch: impl AsRef<Path>, record: &[u8]) -> Option<String> {
        let target = write_target(scratch.as_ref(), record);
        volume_label(&target, &test_boot()).expect("the synthetic record decodes")
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
    fn boot_sector_accepts_synthetic_vbrs() {
        // Every power-of-two cluster size the options admit at 512-byte
        // sectors, plus the 4096-byte-sector corner (65536 / 4096 = 16
        // sectors per cluster). Synthetic only.
        let cases = [
            (512u16, 512u32),
            (512, 1024),
            (512, 4096),
            (512, 16384),
            (512, 65536),
            (4096, 65536),
        ];
        for (bps, cluster) in cases {
            let vbr = synthetic_vbr(bps, cluster);
            let boot = boot_sector(&vbr).expect("the synthetic VBR parses");
            assert_eq!(boot.bytes_per_sector, u32::from(bps));
            assert_eq!(boot.cluster_bytes, cluster);
            assert_eq!(boot.volume_serial, SYNTHETIC_SERIAL);
            // The fixtures carry $MFT at cluster 8 with 0xF6-shaped
            // 1024-byte records; both fields round-trip through the
            // parser, and the 0x28 total sectors back out the exact
            // byte length of the synthetic targets.
            assert_eq!(boot.mft_start_cluster, SYNTHETIC_MFT_CLUSTER);
            assert_eq!(boot.mft_record_bytes, SYNTHETIC_RECORD_BYTES);
            assert_eq!(boot.volume_bytes, SYNTHETIC_TARGET_BYTES);
        }
    }

    #[test]
    fn boot_sector_refuses_a_wrong_magic() {
        let mut vbr = synthetic_vbr(512, 4096);
        vbr[3..11].copy_from_slice(b"FAT32   ");
        let error = boot_sector(&vbr).expect_err("the magic is wrong");
        assert!(error.to_string().contains("NTFS"), "{error}");
    }

    #[test]
    fn boot_sector_refuses_a_bad_sector_size() {
        let vbr = synthetic_vbr(1024, 4096);
        let error = boot_sector(&vbr).expect_err("1024 byte sectors are refused");
        let text = error.to_string();
        assert!(text.contains("1024"), "{text}");
        assert!(text.contains("512"), "{text}");
    }

    #[test]
    fn boot_sector_refuses_a_zero_ratio() {
        let mut vbr = synthetic_vbr(512, 4096);
        vbr[13] = 0;
        let error = boot_sector(&vbr).expect_err("zero sectors per cluster is refused");
        assert!(error.to_string().contains("zero"), "{error}");
    }

    #[test]
    fn boot_sector_refuses_an_oversize_cluster() {
        // 512-byte sectors with the 0xFF ratio: 130560 bytes, past the
        // 65536 ceiling. Synthetic encoding, not a real-tool claim.
        let mut vbr = synthetic_vbr(512, 512);
        vbr[13] = 0xFF;
        let error = boot_sector(&vbr).expect_err("the cluster is too large");
        let text = error.to_string();
        assert!(text.contains("out of range"), "{text}");
        assert!(text.contains("130560"), "{text}");
    }

    #[test]
    fn boot_sector_refuses_a_missing_signature() {
        let mut vbr = synthetic_vbr(512, 4096);
        vbr[510] = 0x00;
        vbr[511] = 0x00;
        let error = boot_sector(&vbr).expect_err("the 55AA signature is missing");
        assert!(error.to_string().contains("0x55"), "{error}");
    }

    #[test]
    fn boot_sector_refuses_non_ntfs_bytes() {
        // A full 512 bytes of vowels: no magic, no fields, no signature.
        // Synthetic garbage, pinned so "any bytes parse" can never creep in.
        let vbr = [b'e'; 512];
        let error = boot_sector(&vbr).expect_err("vowel bytes are not a VBR");
        assert!(error.to_string().contains("NTFS"), "{error}");
    }

    #[test]
    fn options_default_to_4k_clusters() {
        let options = Options::new(Some("LABEL".to_string()));
        assert_eq!(options.cluster_bytes, DEFAULT_CLUSTER_BYTES);
        assert_eq!(options.label.as_deref(), Some("LABEL"));
    }

    #[test]
    fn cluster_sizes_must_be_powers_of_two_in_range() {
        for valid in [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536] {
            Options::new(None)
                .with_cluster_bytes(valid)
                .expect("a power of two in range is accepted");
        }
        for invalid in [0, 1, 511, 513, 1000, 4095, 65535, 65537, 131_072] {
            let error = Options::new(None)
                .with_cluster_bytes(invalid)
                .expect_err("a non-power-of-two or out-of-range size is refused");
            let text = error.to_string();
            assert!(text.contains("power of two"), "{text}");
            assert!(text.contains("512"), "{text}");
            assert!(text.contains("65536"), "{text}");
        }
    }

    #[test]
    fn probe_finds_an_mkntfs_stub() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let stub = write_stub(scratch.path(), "mkntfs", "#!/bin/sh\nexit 0\n");
        let (name, path) = find_tool_in(&probe_dirs(scratch.path())).expect("the stub probes");
        assert_eq!(name, "mkntfs");
        assert_eq!(path, stub);
    }

    #[test]
    fn probe_falls_back_to_mkfs_ntfs() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        write_stub(scratch.path(), "mkfs.ntfs", "#!/bin/sh\nexit 0\n");
        let (name, _) = find_tool_in(&probe_dirs(scratch.path())).expect("the alias probes");
        assert_eq!(name, "mkfs.ntfs");
    }

    #[test]
    fn probe_prefers_mkntfs_over_mkfs_ntfs() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        write_stub(scratch.path(), "mkntfs", "#!/bin/sh\nexit 0\n");
        write_stub(scratch.path(), "mkfs.ntfs", "#!/bin/sh\nexit 0\n");
        let (name, _) = find_tool_in(&probe_dirs(scratch.path())).expect("a stub probes");
        assert_eq!(name, "mkntfs");
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
    fn probe_treats_a_failing_version_check_as_absent() {
        // A +x stub that exits 1 on `--version`: the probe fails, so the
        // scan reports the same package error as the empty directory list.
        // Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        write_stub(scratch.path(), "mkntfs", "#!/bin/sh\nexit 1\n");
        let error =
            find_tool_in(&probe_dirs(scratch.path())).expect_err("the failing probe is absent");
        assert_eq!(
            error.to_string(),
            format!("invalid input: {MISSING_TOOL_HINT}"),
        );
    }

    #[test]
    fn probe_skips_files_that_are_not_executable() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        std::fs::write(scratch.path().join("mkntfs"), "#!/bin/sh\nexit 0\n")
            .expect("the non-executable file writes");
        let error =
            find_tool_in(&probe_dirs(scratch.path())).expect_err("a non-executable is skipped");
        assert!(error.to_string().contains("ntfs-3g"), "{error}");
    }

    #[test]
    fn probe_pins_the_double_dash_version_flag() {
        // The version check sends `--version` (this module's fixed contract)
        // and the stub records its first argument as proof.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let record = scratch.path().join("args");
        let body = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" > '{}'\nexit 0\n",
            record.display()
        );
        write_stub(scratch.path(), "mkntfs", &body);
        let (name, _) = find_tool_in(&probe_dirs(scratch.path())).expect("the stub probes");
        assert_eq!(name, "mkntfs");
        let recorded = std::fs::read_to_string(&record).expect("the stub recorded");
        assert_eq!(recorded.trim(), "--version");
    }

    #[test]
    fn format_drives_the_stub_and_verifies_the_vbr() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(
            scratch.path(),
            "mkntfs",
            "#!/bin/sh\nprintf 'got: %s\\n' \"$*\"\necho stub-stdout-line\necho stub-stderr-line >&2\nexit 0\n",
        );
        // The target carries the full synthetic layout — VBR plus record
        // 3 with the volume-name attribute — so the stub's exit 0 leaves
        // a shape this reader verifies end to end. The stub never
        // touches the target bytes: the read-back below verifies them.
        let target = write_target(scratch.path(), &synthetic_record(&RUFUS_NTFS_UNITS));
        let logger = Logger::new(Level::Trace);
        let options = Options::new(Some("TESTLABEL".to_string()))
            .with_cluster_bytes(4096)
            .expect("4096 is valid");

        let volume = format_with(&target, &options, &logger, "mkntfs", &tool_path)
            .expect("the stub exits 0");
        let boot = volume.boot;
        assert_eq!(boot.bytes_per_sector, 512);
        assert_eq!(boot.cluster_bytes, 4096);
        assert_eq!(boot.volume_serial, SYNTHETIC_SERIAL);
        assert_eq!(volume.label.as_deref(), Some("RUFUS NTFS"));

        let snapshot = logger.snapshot();
        assert!(
            snapshot
                .iter()
                .all(|record| record.target == "ntfs" && record.level == Level::Info),
            "every line is logged at Info under the ntfs target"
        );
        let messages: Vec<&str> = snapshot
            .iter()
            .map(|record| record.message.as_str())
            .collect();
        assert!(messages.contains(&"stub-stdout-line"), "{messages:?}");
        assert!(messages.contains(&"stub-stderr-line"), "{messages:?}");
        // The stub echoes its own argv: pins `-f`, the label flag, the
        // cluster flag and the target path as the last argument.
        let expected = format!("got: -f -L TESTLABEL -c 4096 {}", target.display());
        assert!(messages.contains(&expected.as_str()), "{messages:?}");
        // The final line names the tool, the exit and the verified sizes.
        let summary = messages.last().expect("the summary is logged");
        assert!(summary.contains("mkntfs"), "{summary}");
        assert!(summary.contains("exit status: 0"), "{summary}");
        assert!(summary.contains("512"), "{summary}");
        assert!(summary.contains("4096"), "{summary}");
    }

    #[test]
    fn format_without_a_label_omits_the_label_flag() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(
            scratch.path(),
            "mkntfs",
            "#!/bin/sh\nprintf 'got: %s\\n' \"$*\"\nexit 0\n",
        );
        // A record without a $VOLUME_NAME attribute: the format verifies
        // end to end and the label comes back as `Ok(None)` — the
        // end-attribute-marker-only record shape, read from the target.
        let target = write_target(scratch.path(), &synthetic_record(&[]));
        let logger = Logger::new(Level::Trace);
        let options = Options::new(None);

        let volume = format_with(&target, &options, &logger, "mkntfs", &tool_path)
            .expect("the stub exits 0");
        assert_eq!(volume.label, None, "the unnamed volume carries no label");
        let messages: Vec<String> = logger
            .snapshot()
            .iter()
            .map(|record| record.message.clone())
            .collect();
        assert!(
            messages
                .iter()
                .any(|message| message.contains("no `$VOLUME_NAME` attribute")),
            "{messages:?}"
        );
        let expected = format!("got: -f -c 4096 {}", target.display());
        assert!(messages.contains(&expected), "{messages:?}");
    }

    #[test]
    fn format_failure_carries_the_status_and_the_tail() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(
            scratch.path(),
            "mkntfs",
            "#!/bin/sh\necho wiping\necho\n\
             echo l01 >&2\necho l02 >&2\necho l03 >&2\necho l04 >&2\necho l05 >&2\n\
             echo l06 >&2\necho l07 >&2\necho l08 >&2\necho l09 >&2\necho l10 >&2\n\
             exit 3\n",
        );
        // No target file is created: the run fails before any read-back.
        let target = scratch.path().join("missing.bin");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(Some("TESTLABEL".to_string()));

        let error = format_with(&target, &options, &logger, "mkntfs", &tool_path)
            .expect_err("the stub exits 3");
        let text = error.to_string();
        assert!(text.contains("exit status: 3"), "{text}");
        assert!(text.contains("l10"), "{text}");
        assert!(text.contains("l03"), "{text}");
        assert!(!text.contains("l01"), "{text}");
        assert!(!text.contains("l02"), "{text}");
        assert!(
            !text.contains("wiping"),
            "stdout lines are logged, never part of the refusal: {text}"
        );

        // The stdout lines were still logged before the failure, and the
        // blank echo never became a record.
        let messages: Vec<String> = logger
            .snapshot()
            .iter()
            .map(|record| record.message.clone())
            .collect();
        assert!(messages.contains(&"wiping".to_string()), "{messages:?}");
        assert!(
            messages.iter().all(|message| !message.is_empty()),
            "{messages:?}"
        );
    }

    #[test]
    fn boot_sector_refuses_a_zero_mft_start() {
        let mut vbr = synthetic_vbr(512, 4096);
        vbr[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());
        let error = boot_sector(&vbr).expect_err("a zero $MFT start cluster is refused");
        let text = error.to_string();
        assert!(text.contains("$MFT"), "{text}");
        assert!(text.contains("zero"), "{text}");
    }

    #[test]
    fn boot_sector_refuses_zero_total_sectors() {
        // Offset 0x28 zeroed: the VBR would declare an empty volume,
        // which leaves nothing for the label read's bounds arithmetic.
        let mut vbr = synthetic_vbr(512, 4096);
        vbr[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        let error = boot_sector(&vbr).expect_err("a zero total-sector field is refused");
        let text = error.to_string();
        assert!(text.contains("zero"), "{text}");
        assert!(text.contains("empty volume"), "{text}");
    }

    #[test]
    fn boot_sector_refuses_a_volume_length_overflow() {
        // u64::MAX total sectors times the sector size cannot land in a
        // u64: the pre-multiplied volume length refuses instead of
        // wrapping the arithmetic the label read would run.
        let mut vbr = synthetic_vbr(512, 4096);
        vbr[0x28..0x30].copy_from_slice(&u64::MAX.to_le_bytes());
        let error = boot_sector(&vbr).expect_err("total sectors times sector size overflows");
        assert!(error.to_string().contains("overflow"), "{error}");
    }

    #[test]
    fn boot_sector_accepts_mft_record_shapes() {
        // Positive cluster counts that land on a power of two inside the
        // window, and negative exponents at both window edges (0xF0 =
        // 2^16 = 65536, 0xF6 = 2^10 = 1024). On-disk format shapes, pinned
        // by synthetic bytes only.
        let cases: [(u8, u32, u32); 3] =
            [(0xF6, 4096, 1024), (0x01, 4096, 4096), (0xF0, 4096, 65536)];
        for (byte, cluster, expected) in cases {
            let mut vbr = synthetic_vbr(512, cluster);
            vbr[0x40] = byte;
            let boot = boot_sector(&vbr).expect("the shape is accepted");
            assert_eq!(boot.mft_record_bytes, expected, "byte {byte:02X}");
        }
    }

    #[test]
    fn boot_sector_refuses_bad_mft_record_shapes() {
        // Positive encodings: zero count, a product under 1024, a
        // non-power-of-two product, a product past 65536. Negative
        // encodings: tiny exponents, the 2^17 break of the ceiling and the
        // absurd 0x86 exponent (2^122). Synthetic only.
        let cases: [(u8, u32, &str); 6] = [
            (0x00, 4096, "zero"),
            (0x01, 512, "512"),
            (0x03, 4096, "12288"),
            (0x02, 65536, "131072"),
            (0xEF, 4096, "2^17"),
            (0x86, 4096, "2^122"),
        ];
        for (byte, cluster, needle) in cases {
            let mut vbr = synthetic_vbr(512, cluster);
            vbr[0x40] = byte;
            let error = boot_sector(&vbr).expect_err("the shape is refused");
            let text = error.to_string();
            assert!(text.contains(needle), "{needle:?} in {text}");
        }
    }

    #[test]
    fn format_reads_the_volume_label_from_record_three() {
        // The round trip: a success stub plus a target whose VBR (with
        // the $MFT fields) and whose record 3 — 1024 bytes, correct
        // `FILE` magic, fixups and one resident 0x60 attribute carrying
        // UTF-16LE "RUFUS NTFS" — verify end to end.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(scratch.path(), "mkntfs", "#!/bin/sh\nexit 0\n");
        let target = write_target(scratch.path(), &synthetic_record(&RUFUS_NTFS_UNITS));
        let logger = Logger::new(Level::Trace);
        let options = Options::new(Some("RUFUS NTFS".to_string()))
            .with_cluster_bytes(4096)
            .expect("4096 is valid");

        let volume = format_with(&target, &options, &logger, "mkntfs", &tool_path)
            .expect("the formatted shape verifies end to end");
        assert_eq!(volume.boot.bytes_per_sector, 512);
        assert_eq!(volume.boot.cluster_bytes, 4096);
        assert_eq!(
            volume.label.as_deref(),
            Some("RUFUS NTFS"),
            "the label round-trips out of record 3 ({volume:?})"
        );
        // The logger names the label at Info under the ntfs target.
        let record = logger
            .snapshot()
            .into_iter()
            .find(|record| record.message.contains("RUFUS NTFS"))
            .expect("a log line names the label");
        assert_eq!(record.level, Level::Info);
        assert_eq!(record.target, "ntfs");
        assert!(
            record.message.contains("`RUFUS NTFS`"),
            "{}",
            record.message
        );
    }

    #[test]
    fn format_logs_a_failed_label_read_before_refusing() {
        // Label-READ failure after a successful stub run is a hard
        // refusal, logged at Error before it surfaces; here the VBR
        // points $MFT past the volume it declares, so only the VBR
        // verifies. The refusal is the declared-volume bounds check,
        // and the wrapper passes it through unchanged.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(scratch.path(), "mkntfs", "#!/bin/sh\nexit 0\n");
        let mut vbr = synthetic_vbr(512, 4096);
        vbr[0x30..0x38].copy_from_slice(&128u64.to_le_bytes());
        let target = scratch.path().join("short-$mft.bin");
        std::fs::write(&target, vbr).expect("the target VBR writes");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(None);

        let error = format_with(&target, &options, &logger, "mkntfs", &tool_path)
            .expect_err("the label read is a hard refusal after a successful run");
        assert!(matches!(error, CoreError::InvalidInput { .. }), "{error}");
        // The refusal is the last record: the summary never logged past it.
        let snapshot = logger.snapshot();
        let last = snapshot.last().expect("the failure is logged");
        assert_eq!(last.level, Level::Error);
        assert_eq!(last.target, "ntfs");
        assert!(
            last.message.contains("could not be verified"),
            "{}",
            last.message
        );
        assert!(last.message.contains("527360"), "{}", last.message);
    }

    #[test]
    fn format_after_a_short_target_surfaces_the_io_refusal() {
        // Carried review observation: a target shorter than the VBR dies
        // in `read_exact_at` AFTER a successful tool run, surfaced as the
        // house `CoreError::io` naming the path and the io source.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(scratch.path(), "mkntfs", "#!/bin/sh\nexit 0\n");
        let target = scratch.path().join("tiny.bin");
        std::fs::write(&target, [b'e'; 100]).expect("the short target writes");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(None);

        let error = format_with(&target, &options, &logger, "mkntfs", &tool_path)
            .expect_err("the 100-byte target cannot yield a VBR");
        let text = error.to_string();
        assert!(matches!(error, CoreError::Io { .. }), "{text}");
        assert!(text.contains(&target.display().to_string()), "{text}");
        // `read_exact_at`'s UnexpectedEof surfaces with the source's own
        // text; the test pins the whole house shape: path + source.
        assert!(text.contains("failed to fill whole buffer"), "{text}");
        let CoreError::Io { source, .. } = &error else {
            panic!("the error is the house io variant: {text}")
        };
        assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn volume_label_refuses_an_mft_beyond_the_declared_volume() {
        // $MFT at cluster 128 of a volume the VBR declares as 72 * 512 =
        // 36864 bytes: record 3 (1024 bytes) cannot end inside that
        // declared length, and the refusal names the byte window plus
        // the declared volume length. The check reads the VBR's own
        // declaration, not the 512-byte file's metadata length.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let mut vbr = synthetic_vbr(512, 4096);
        vbr[0x30..0x38].copy_from_slice(&128u64.to_le_bytes());
        let target = scratch.path().join("mft-outside.bin");
        std::fs::write(&target, vbr).expect("the target VBR writes");
        let boot = boot_sector(&vbr).expect("the custom VBR parses");

        let error =
            volume_label(&target, &boot).expect_err("the $MFT lies beyond the declared volume");
        let text = error.to_string();
        eprintln!("MEASUREMENT-BOUNDS: {text}");
        // 128 * 4096 + 3 * 1024 = 527360; + 1024 = 528384; the VBR
        // declares 72 * 512 = 36864 bytes.
        assert!(text.contains("527360"), "{text}");
        assert!(text.contains("528384"), "{text}");
        assert!(text.contains("36864"), "{text}");
    }

    #[test]
    fn volume_label_refuses_a_short_file_below_the_declared_volume() {
        // The record-3 window fits the declared volume but runs past
        // the end of the actual 512-byte file: the bounds check passes
        // on the VBR's declaration alone, and the exact read hits the
        // io shortfall instead — the refusal is the house io variant,
        // not a metadata-length refusal (no length is stat'd anymore).
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let vbr = synthetic_vbr(512, 4096);
        let target = scratch.path().join("short-under-declared.bin");
        std::fs::write(&target, vbr).expect("the target VBR writes");
        let boot = boot_sector(&vbr).expect("the synthetic VBR parses");

        let error =
            volume_label(&target, &boot).expect_err("the record read runs past the file's own end");
        let text = error.to_string();
        eprintln!("MEASUREMENT-IO: {text}");
        assert!(matches!(error, CoreError::Io { .. }), "{text}");
        assert!(text.contains(&target.display().to_string()), "{text}");
        // `read_exact_at`'s UnexpectedEof surfaces with the source's
        // own text; the test pins the whole house shape: path + source.
        assert!(text.contains("failed to fill whole buffer"), "{text}");
        let CoreError::Io { source, .. } = &error else {
            panic!("the error is the house io variant: {text}")
        };
        assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn volume_label_refuses_a_wrong_fixup_count() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let text = label_refusal_text(&scratch, |record| {
            record[6..8].copy_from_slice(&4u16.to_le_bytes());
        });
        assert!(text.contains("4 fixup entries"), "{text}");
        assert!(text.contains("implies 3"), "{text}");
    }

    #[test]
    fn volume_label_refuses_a_fixup_signature_mismatch_at_either_block() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let first = label_refusal_text(&scratch, |record| {
            record[510..512].copy_from_slice(&0x7777u16.to_le_bytes());
        });
        assert!(first.contains("0x7777"), "{first}");
        assert!(first.contains("0x0001"), "{first}");
        let second = label_refusal_text(&scratch, |record| {
            record[1022..1024].copy_from_slice(&0x7777u16.to_le_bytes());
        });
        assert!(second.contains("1022"), "{second}");
    }

    #[test]
    fn volume_label_refuses_damaged_file_magic() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let text = label_refusal_text(&scratch, |record| {
            record[0] = 0;
        });
        assert!(text.contains("`FILE`"), "{text}");
    }

    #[test]
    fn volume_label_refuses_a_zero_length_attribute() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let text = label_refusal_text(&scratch, |record| {
            record[60..64].copy_from_slice(&0u32.to_le_bytes());
        });
        assert!(text.contains("declares length 0"), "{text}");
    }

    #[test]
    fn volume_label_refuses_a_walk_overrun() {
        // A non-name attribute whose length steps past the record never
        // reaches an end marker. Synthetic only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let text = label_refusal_text(&scratch, |record| {
            record[56..60].copy_from_slice(&0x0000_0010u32.to_le_bytes());
            record[60..64].copy_from_slice(&2000u32.to_le_bytes());
        });
        assert!(text.contains("extends past"), "{text}");
    }

    #[test]
    fn volume_label_refuses_a_non_resident_name() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let text = label_refusal_text(&scratch, |record| {
            record[64] = 1;
        });
        assert!(text.contains("non-resident"), "{text}");
    }

    #[test]
    fn volume_label_refuses_an_odd_length_label() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let text = label_refusal_text(&scratch, |record| {
            record[72..76].copy_from_slice(&11u32.to_le_bytes());
        });
        assert!(text.contains("odd"), "{text}");
        assert!(text.contains("11"), "{text}");
    }

    #[test]
    fn volume_label_refuses_a_label_past_the_attribute_span() {
        // The value offset is attribute-relative: 900 puts the label
        // bytes at record 56 + 900 = 956, and 128 more bytes run right
        // past the attribute's own 44-byte window (56..100) even though
        // they would still fit the 1024-byte record.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let text = label_refusal_text(&scratch, |record| {
            record[76..78].copy_from_slice(&900u16.to_le_bytes());
            record[72..76].copy_from_slice(&128u32.to_le_bytes());
        });
        assert!(text.contains("956"), "{text}");
        assert!(text.contains("1084"), "{text}");
        assert!(text.contains("56..100"), "{text}");
    }

    #[test]
    fn volume_label_refuses_a_label_inside_the_named_header() {
        // A named $VOLUME_NAME attribute: 4 UTF-16 name units at
        // attribute offset 24 push the resident floor to 24 + 4*2 = 32
        // attribute bytes, and the value offset still at 24 overlaps the
        // name's own window — refused before any window arithmetic.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let text = label_refusal_text(&scratch, |record| {
            record[65] = 4;
            record[66..68].copy_from_slice(&24u16.to_le_bytes());
        });
        assert!(text.contains("24"), "{text}");
        assert!(text.contains("32"), "{text}");
    }

    #[test]
    fn volume_label_refuses_a_walk_past_bytes_in_use() {
        // bytes_in_use below the attributes offset: the walker position
        // 56 is already past the declared 30 bytes and no end marker
        // ever appeared. Synthetic only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let text = label_refusal_text(&scratch, |record| {
            record[24..28].copy_from_slice(&30u32.to_le_bytes());
        });
        assert!(text.contains("56"), "{text}");
        assert!(text.contains("30"), "{text}");
    }

    #[test]
    fn volume_label_refuses_bytes_in_use_beyond_the_record() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let text = label_refusal_text(&scratch, |record| {
            record[24..28].copy_from_slice(&2000u32.to_le_bytes());
        });
        assert!(text.contains("2000"), "{text}");
        assert!(text.contains("1024"), "{text}");
    }

    #[test]
    fn volume_label_refuses_an_array_past_the_protected_tail() {
        // Update sequence invariant: the array must finish before the
        // first protected block tail at record offset 510. An array at
        // 510 with 3 entries ends at 516 — refused with both numbers.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let text = label_refusal_text(&scratch, |record| {
            record[4..6].copy_from_slice(&510u16.to_le_bytes());
        });
        assert!(text.contains("516"), "{text}");
        assert!(text.contains("510"), "{text}");
    }

    #[test]
    fn volume_label_refuses_a_label_longer_than_512_bytes() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let text = label_refusal_text(&scratch, |record| {
            record[72..76].copy_from_slice(&600u32.to_le_bytes());
        });
        assert!(text.contains("600"), "{text}");
        assert!(text.contains("512"), "{text}");
    }

    #[test]
    fn volume_label_takes_the_first_name_attribute() {
        // A second $VOLUME_NAME attribute behind the first never wins:
        // the walk returns on the first.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        // "OTHER" as UTF-16LE units.
        const OTHER_UNITS: [u16; 5] = [0x004F, 0x0054, 0x0048, 0x0045, 0x0052];
        let mut record = synthetic_record(&RUFUS_NTFS_UNITS);
        // The first attribute spans 56..100 (length = 24 header bytes +
        // 10 label bytes = 44) and the end marker sits at 100..104, so
        // the second attribute starts at 104 (type 0x60, length 24 + 10
        // = 34) and carries its value at attribute offset 24 — record
        // bytes 128..138. Decorated by this mutator, never read: the
        // walk returns on the first name attribute.
        record[104..108].copy_from_slice(&TYPE_VOLUME_NAME.to_le_bytes());
        record[108..112].copy_from_slice(&(24 + OTHER_UNITS.len() as u32 * 2).to_le_bytes());
        record[120..124].copy_from_slice(&10u32.to_le_bytes());
        record[124..126].copy_from_slice(&24u16.to_le_bytes());
        for (i, unit) in OTHER_UNITS.iter().enumerate() {
            let at = 128 + 2 * i;
            record[at..at + 2].copy_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(
            label_of_record(scratch.path(), &record),
            Some("RUFUS NTFS".to_string()),
            "the first name attribute wins"
        );
    }

    #[test]
    fn volume_label_decodes_a_zero_padded_value_verbatim() {
        // No trimming in code: the zero-padding unit stays in the decoded
        // label (the lossy decode keeps it, and the reader trims nothing);
        // the synthetic fixture pins that choice.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let record = synthetic_record(&[0x0041, 0x0042, 0x0000]);
        assert_eq!(
            label_of_record(scratch.path(), &record),
            Some("AB\u{0}".to_string()),
            "the trailing NUL unit is kept verbatim"
        );
    }

    #[test]
    fn volume_label_restores_fixup_saved_values() {
        // The label value deliberately straddles the second fixup slot,
        // by way of a leading filler attribute: the filler (type 0x10,
        // resident) spans 56..992 (length 936), the $VOLUME_NAME
        // attribute spans 992..1024 (length = 24 header bytes + 8 value
        // bytes, byte-exact to the record end), and its value offset 24
        // (attribute-relative, per the resident header layout) puts the
        // value bytes at record offset 992 + 24 = 1016..1024: 'Z', 'W'
        // and 'X' sit in plain bytes while the fourth UTF-16 unit lives
        // exactly in the stored sequence slot 1022..1024. A decode
        // without the saved-value restore would read U+0001 there instead
        // of the synthetic '!' (the array's second saved entry, 0x0021),
        // so the label proving "ZWX!" pins that the trailing slots were
        // checked against the sequence value and patched back. The walk
        // bounds keep this large shape legal: bytes_in_use is 1024 and
        // the walker returns on the 0x60 before stepping past it.
        // Synthetic record layout, not a real-tool claim.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let mut record = vec![0u8; SYNTHETIC_RECORD_BYTES as usize];
        record[0..4].copy_from_slice(b"FILE");
        record[4..6].copy_from_slice(&SYNTHETIC_USA_OFFSET.to_le_bytes());
        record[6..8].copy_from_slice(&3u16.to_le_bytes());
        record[20..22].copy_from_slice(&56u16.to_le_bytes());
        record[48..50].copy_from_slice(&SYNTHETIC_USA_VALUE.to_le_bytes());
        record[50..52].copy_from_slice(&0xA55A_u16.to_le_bytes());
        // array entry 2 = 0x0021 ("!"): the value restored into the
        // second trailing slot.
        record[52..54].copy_from_slice(&0x0021u16.to_le_bytes());
        record[510..512].copy_from_slice(&SYNTHETIC_USA_VALUE.to_le_bytes());
        record[1022..1024].copy_from_slice(&SYNTHETIC_USA_VALUE.to_le_bytes());
        // bytes_in_use covers the attributes through the name attribute:
        // the walker returns on the 0x60 at record offset 992 before any
        // further position.
        record[24..28].copy_from_slice(&1024u32.to_le_bytes());
        // Filler attribute 56..992: a resident non-name type the walk
        // steps over.
        record[56..60].copy_from_slice(&0x0000_0010u32.to_le_bytes());
        record[60..64].copy_from_slice(&936u32.to_le_bytes());
        record[64] = 0;
        // $VOLUME_NAME 992..1024: value offset 24 = attribute-relative
        // (0x18), so the UTF-16LE value lands at record 1016..1024.
        record[992..996].copy_from_slice(&TYPE_VOLUME_NAME.to_le_bytes());
        record[996..1000].copy_from_slice(&32u32.to_le_bytes());
        record[1000] = 0;
        record[1008..1012].copy_from_slice(&8u32.to_le_bytes());
        record[1012..1014].copy_from_slice(&24u16.to_le_bytes());
        record[1016..1018].copy_from_slice(&0x005A_u16.to_le_bytes());
        record[1018..1020].copy_from_slice(&0x0057_u16.to_le_bytes());
        record[1020..1022].copy_from_slice(&0x0058_u16.to_le_bytes());
        // record[1022..1024] already holds the stored sequence value the
        // fixup check compares against; the restore turns it into '!'.
        assert_eq!(
            label_of_record(scratch.path(), &record),
            Some("ZWX!".to_string()),
            "the saved fixup value was restored into the second trailing slot"
        );
    }
}
