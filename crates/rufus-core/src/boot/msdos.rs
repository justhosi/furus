//! MS-DOS install: the `IO.SYS`, `MSDOS.SYS` and `COMMAND.COM` files
//! at the volume root, with the WinME real-mode jump patch applied.
//!
//! Reference behaviour, verified against upstream `src/dos.c` and the
//! 4.15 binary (the PLAN's "patch the COMMAND.COM OEM/label bytes"
//! wording is wrong — corrected below): Rufus cannot bundle MS-DOS
//! for licensing reasons, so it extracts the crippled DOS of WinME
//! from a FAT12 floppy image carried inside `diskcopy.dll`, reusing
//! its own previously downloaded copy at `%LOCALAPPDATA%\Rufus\diskcopy.dll`
//! when one is present (`src/rufus.c:1982-1990`). This port holds no
//! such cache and bundles nothing: the caller supplies the three
//! extracted files and [`MsDosFiles::load`] reads them.
//!
//! The reference walks every root entry of the floppy image and
//! extracts the matches in that order (`ExtractMSDOS`,
//! `src/dos.c:323-331`); the `extractlist[]` table (`src/dos.c:298`)
//! is only the name-matching table, not an order. MS-DOS reads
//! `IO.SYS` from the front of the root directory and requires its
//! cluster chain to be contiguous, so this module makes that
//! explicit: it writes the patched `IO.SYS` first — the first root
//! entry when the root is otherwise empty — through
//! [`Fat32::allocate_contiguous`] plus [`Fat32::link_file`], and only
//! then `MSDOS.SYS` and `COMMAND.COM` through the ordinary
//! `create_file`/`write_at` path. Every write keeps the
//! keep-if-identical policy of
//! [`install_loader`](super::kolibri::install_loader): a file already
//! present with byte-identical content counts as kept and nothing is
//! written; differing bytes refuse naming the file.
//!
//! The patch turns a short conditional jump into an unconditional one
//! (`0x75` to `0xEB`), enabling real-mode DOS in the WinME binaries:
//! `IO.SYS` expects [`IO_SYS_BYTES`] bytes (`0x1C800`) carrying
//! [`IO_SYS_SIGNATURE`] at [`IO_SYS_SIGNATURE_OFFSET`] (`0x3A8`), and
//! the byte at [`IO_SYS_PATCH_OFFSET`] (`0x3AA`, the `0x75`) becomes
//! [`IO_SYS_PATCHED`]; `COMMAND.COM` expects [`COMMAND_COM_BYTES`]
//! bytes (`0x16B70`) carrying [`COMMAND_COM_SIGNATURE`] at
//! [`COMMAND_COM_SIGNATURE_OFFSET`] (`0x650C`), and the byte at
//! [`COMMAND_COM_PATCH_OFFSET`] (`0x6510`, the `0x75`) becomes
//! [`COMMAND_COM_PATCHED`]. A size or signature mismatch is not an
//! error — the reference ignores a failed patch and copies the file
//! unchanged, logging `Patching IO.SYS...` / `Patching COMMAND.COM...`
//! and, on mismatch, `  unexpected file size` or
//! `  unexpected binary data` — so the bytes return verbatim and the
//! [`PatchState`] records which shape missed; [`PatchState::note`]
//! replays the reference log text.
//!
//! A cluster of 65536 bytes or more cannot boot MS-DOS:
//! [`check_cluster_size`] refuses it with the reference MSG_110
//! sentence (`src/rufus.c:1978-1983`).
//!
//! Honest gaps, stated plainly: a plain run carries no MS-DOS files
//! and [`MsDosFiles::load`] refuses until the caller supplies them;
//! this module writes no boot record (the FAT32 formatter's standard
//! record stands); a stick built from this slice alone is bootable
//! only if the caller supplies bootable WinME/DOS files with the
//! expected layout. The only torn state is a partial file set: a
//! failure between `IO.SYS` and the rest leaves the earlier files
//! behind, but nothing writes a boot record, so nothing becomes
//! half-bootable. Nothing here flushes: the caller owns the flush,
//! the same convention as
//! [`install_loader`](super::kolibri::install_loader).

use std::path::Path;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::fat32::Fat32;

/// File name of the DOS BIOS at the volume root (`src/dos.c` creates
/// it at the target root).
pub const IO_SYS: &str = "IO.SYS";

/// File name of the DOS kernel at the volume root (`src/dos.c`
/// creates it at the target root).
pub const MSDOS_SYS: &str = "MSDOS.SYS";

/// File name of the command interpreter at the volume root
/// (`src/dos.c` creates it at the target root).
pub const COMMAND_COM: &str = "COMMAND.COM";

/// Destination path of `IO.SYS` on the volume: the volume root.
pub const IO_SYS_PATH: &str = "/IO.SYS";

/// Destination path of `MSDOS.SYS` on the volume: the volume root.
pub const MSDOS_SYS_PATH: &str = "/MSDOS.SYS";

/// Destination path of `COMMAND.COM` on the volume: the volume root.
pub const COMMAND_COM_PATH: &str = "/COMMAND.COM";

/// Expected `IO.SYS` byte count: 116736 (`0x1C800`), the WinME
/// `IO.SYS` size `src/dos.c` patches.
pub const IO_SYS_BYTES: usize = 116_736;

/// Offset of the 8-byte reference window in `IO.SYS` (`0x3A8`): the
/// bytes there must equal [`IO_SYS_SIGNATURE`] before the patch.
pub const IO_SYS_SIGNATURE_OFFSET: usize = 0x3A8;

/// The 8 bytes `src/dos.c` expects at [`IO_SYS_SIGNATURE_OFFSET`]:
/// `FA 80 75 09 8D B6 99 00`.
pub const IO_SYS_SIGNATURE: [u8; 8] = [0xFA, 0x80, 0x75, 0x09, 0x8D, 0xB6, 0x99, 0x00];

/// Offset of the patched byte in `IO.SYS` (`0x3AA`): the `0x75` inside
/// the signature window.
pub const IO_SYS_PATCH_OFFSET: usize = 0x3AA;

/// The byte the patch writes (`0xEB`): the short conditional jump
/// becomes unconditional.
pub const IO_SYS_PATCHED: u8 = 0xEB;

/// Expected `COMMAND.COM` byte count: 93040 (`0x16B70`), the WinME
/// `COMMAND.COM` size `src/dos.c` patches.
pub const COMMAND_COM_BYTES: usize = 93_040;

/// Offset of the 8-byte reference window in `COMMAND.COM` (`0x650C`):
/// the bytes there must equal [`COMMAND_COM_SIGNATURE`] before the
/// patch.
pub const COMMAND_COM_SIGNATURE_OFFSET: usize = 0x650C;

/// The 8 bytes `src/dos.c` expects at
/// [`COMMAND_COM_SIGNATURE_OFFSET`]: `15 80 FA 03 75 10 B8 0E`.
pub const COMMAND_COM_SIGNATURE: [u8; 8] = [0x15, 0x80, 0xFA, 0x03, 0x75, 0x10, 0xB8, 0x0E];

/// Offset of the patched byte in `COMMAND.COM` (`0x6510`): the `0x75`
/// inside the signature window.
pub const COMMAND_COM_PATCH_OFFSET: usize = 0x6510;

/// The byte the patch writes (`0xEB`): the short conditional jump
/// becomes unconditional.
pub const COMMAND_COM_PATCHED: u8 = 0xEB;

/// Read cap per file in bytes (8 MiB): hostile-input defence for
/// [`MsDosFiles::load`], well above the 116736/93040 expectations,
/// so no crafted multi-gigabyte file is ever buffered.
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Whether the patch landed or which reference check missed.
///
/// A mismatch is not an error: the file is then copied verbatim, and
/// this state tells the caller which log line the reference would
/// have printed (see [`PatchState::note`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchState {
    /// Size and signature matched; exactly one byte differs from the
    /// input (the patch offset now carries `0xEB`).
    Applied,
    /// The input length missed the expectation; `observed` is the
    /// length seen.
    UnexpectedSize {
        /// Byte count of the input that missed.
        observed: u64,
    },
    /// The length matched but the signature window did not.
    UnexpectedSignature,
}

impl PatchState {
    /// The reference log text for a missed patch (`  unexpected file
    /// size` / `  unexpected binary data`, two leading spaces), or
    /// `None` when the patch applied. ASCII by construction.
    #[must_use]
    pub fn note(&self) -> Option<&'static str> {
        match self {
            Self::Applied => None,
            Self::UnexpectedSize { .. } => Some("  unexpected file size"),
            Self::UnexpectedSignature => Some("  unexpected binary data"),
        }
    }
}

/// Patch output: the bytes to write plus how they came to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patched {
    bytes: Vec<u8>,
    state: PatchState,
}

impl Patched {
    /// The bytes to write: patched on [`PatchState::Applied`],
    /// verbatim on either mismatch.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether the patch landed or which check missed.
    #[must_use]
    pub fn state(&self) -> PatchState {
        self.state
    }
}

/// Patch one file's bytes: length, then the signature window, then
/// the single-byte write. Shared by [`patch_io_sys`] and
/// [`patch_command_com`]; the constants above carry the per-file
/// reference provenance.
fn patch_bytes(
    bytes: &[u8],
    expected_len: usize,
    signature_offset: usize,
    signature: &[u8; 8],
    patch_offset: usize,
    patched: u8,
) -> Patched {
    if bytes.len() != expected_len {
        return Patched {
            bytes: bytes.to_vec(),
            state: PatchState::UnexpectedSize {
                observed: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            },
        };
    }
    let window_end = signature_offset.saturating_add(signature.len());
    let matches = match bytes.get(signature_offset..window_end) {
        Some(window) => window == signature.as_slice(),
        None => false,
    };
    if !matches {
        return Patched {
            bytes: bytes.to_vec(),
            state: PatchState::UnexpectedSignature,
        };
    }
    let mut out = bytes.to_vec();
    if let Some(slot) = out.get_mut(patch_offset) {
        *slot = patched;
    } else {
        // Unreachable with the documented constants (both patch
        // offsets sit inside their expected lengths), but an
        // out-of-range write must never panic: report the miss and
        // hand the bytes back verbatim.
        return Patched {
            bytes: out,
            state: PatchState::UnexpectedSignature,
        };
    }
    Patched {
        bytes: out,
        state: PatchState::Applied,
    }
}

/// Patch `IO.SYS` bytes: [`IO_SYS_SIGNATURE`] at
/// [`IO_SYS_SIGNATURE_OFFSET`] (`0x3A8`), then `0xEB` at
/// [`IO_SYS_PATCH_OFFSET`] (`0x3AA`).
///
/// On [`PatchState::Applied`] exactly one byte differs from the
/// input; on either mismatch the bytes return unchanged.
#[must_use]
pub fn patch_io_sys(bytes: &[u8]) -> Patched {
    patch_bytes(
        bytes,
        IO_SYS_BYTES,
        IO_SYS_SIGNATURE_OFFSET,
        &IO_SYS_SIGNATURE,
        IO_SYS_PATCH_OFFSET,
        IO_SYS_PATCHED,
    )
}

/// Patch `COMMAND.COM` bytes: [`COMMAND_COM_SIGNATURE`] at
/// [`COMMAND_COM_SIGNATURE_OFFSET`] (`0x650C`), then `0xEB` at
/// [`COMMAND_COM_PATCH_OFFSET`] (`0x6510`).
///
/// On [`PatchState::Applied`] exactly one byte differs from the
/// input; on either mismatch the bytes return unchanged.
#[must_use]
pub fn patch_command_com(bytes: &[u8]) -> Patched {
    patch_bytes(
        bytes,
        COMMAND_COM_BYTES,
        COMMAND_COM_SIGNATURE_OFFSET,
        &COMMAND_COM_SIGNATURE,
        COMMAND_COM_PATCH_OFFSET,
        COMMAND_COM_PATCHED,
    )
}

/// Refuse a cluster size MS-DOS cannot boot from: 65536 bytes or more
/// (`src/rufus.c:1978-1983`, MSG_110).
///
/// The refusal carries the reference sentence verbatim.
pub fn check_cluster_size(cluster_bytes: u32) -> Result<()> {
    if cluster_bytes >= 65_536 {
        return Err(CoreError::invalid(
            "MS-DOS cannot boot from a drive using a 64 kilobytes Cluster size.".to_string(),
        ));
    }
    Ok(())
}

/// The three caller-supplied MS-DOS files: nothing is bundled, so a
/// plain run has no bytes and [`load`](Self::load) refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsDosFiles {
    io_sys: Vec<u8>,
    msdos_sys: Vec<u8>,
    command_com: Vec<u8>,
}

impl MsDosFiles {
    /// The `IO.SYS` bytes.
    #[must_use]
    pub fn io_sys(&self) -> &[u8] {
        &self.io_sys
    }

    /// The `MSDOS.SYS` bytes.
    #[must_use]
    pub fn msdos_sys(&self) -> &[u8] {
        &self.msdos_sys
    }

    /// The `COMMAND.COM` bytes.
    #[must_use]
    pub fn command_com(&self) -> &[u8] {
        &self.command_com
    }

    /// Read the three files from `dir`, matching names
    /// ASCII-case-insensitively (a directory listing of `dir`).
    ///
    /// A missing file refuses naming it: it must be supplied by the
    /// user because MS-DOS cannot be bundled. A real I/O error
    /// (unreadable directory or file) propagates with its path. An
    /// entry that is not a regular file (a directory or a symlink of
    /// that name) refuses naming it, and anything longer than
    /// [`MAX_FILE_BYTES`] refuses naming the file and both sizes.
    pub fn load(dir: &Path) -> Result<MsDosFiles> {
        let io_sys = read_one(dir, IO_SYS)?;
        let msdos_sys = read_one(dir, MSDOS_SYS)?;
        let command_com = read_one(dir, COMMAND_COM)?;
        Ok(MsDosFiles {
            io_sys,
            msdos_sys,
            command_com,
        })
    }
}

/// Read the file named `name` from `dir` (ASCII-case-insensitive),
/// enforcing the [`MsDosFiles::load`] contract.
fn read_one(dir: &Path, name: &'static str) -> Result<Vec<u8>> {
    let listing = std::fs::read_dir(dir).map_err(|source| CoreError::io(dir, source))?;
    let mut found: Option<std::path::PathBuf> = None;
    for entry in listing {
        let entry = entry.map_err(|source| CoreError::io(dir, source))?;
        if entry
            .file_name()
            .to_string_lossy()
            .eq_ignore_ascii_case(name)
        {
            found = Some(entry.path());
            break;
        }
    }
    let path = found.ok_or_else(|| {
        CoreError::invalid(format!(
            "msdos file '{name}' is missing from '{}': it must be supplied by the user because MS-DOS cannot be bundled: refusing",
            dir.display()
        ))
    })?;
    let meta = std::fs::symlink_metadata(&path).map_err(|source| CoreError::io(&path, source))?;
    if !meta.file_type().is_file() {
        return Err(CoreError::invalid(format!(
            "msdos file '{name}' at '{}' is not a regular file: refusing",
            path.display()
        )));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(CoreError::invalid(format!(
            "msdos file '{name}' is {} bytes, over the {MAX_FILE_BYTES} byte read cap: refusing",
            meta.len()
        )));
    }
    let bytes = std::fs::read(&path).map_err(|source| CoreError::io(&path, source))?;
    let actual = u64::try_from(bytes.len()).map_err(|_| {
        CoreError::invalid(format!("msdos file '{name}' is longer than u64: refusing"))
    })?;
    if actual > MAX_FILE_BYTES {
        return Err(CoreError::invalid(format!(
            "msdos file '{name}' is {actual} bytes, over the {MAX_FILE_BYTES} byte read cap: refusing"
        )));
    }
    Ok(bytes)
}

/// What [`install`] wrote: the three byte counts, both patch states,
/// and which files were already identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    io_sys: u64,
    msdos_sys: u64,
    command_com: u64,
    io_sys_patch: PatchState,
    command_com_patch: PatchState,
    kept: Vec<&'static str>,
}

impl Installed {
    /// Bytes of `/IO.SYS` (the patched length, which always equals
    /// the supplied length).
    #[must_use]
    pub fn io_sys(&self) -> u64 {
        self.io_sys
    }

    /// Bytes of `/MSDOS.SYS`.
    #[must_use]
    pub fn msdos_sys(&self) -> u64 {
        self.msdos_sys
    }

    /// Bytes of `/COMMAND.COM` (the patched length, which always
    /// equals the supplied length).
    #[must_use]
    pub fn command_com(&self) -> u64 {
        self.command_com
    }

    /// How the `IO.SYS` patch went (a miss still wrote the file
    /// verbatim).
    #[must_use]
    pub fn io_sys_patch(&self) -> PatchState {
        self.io_sys_patch
    }

    /// How the `COMMAND.COM` patch went (a miss still wrote the file
    /// verbatim).
    #[must_use]
    pub fn command_com_patch(&self) -> PatchState {
        self.command_com_patch
    }

    /// Names of the files that already held byte-identical content
    /// and were kept without a write, in install order.
    #[must_use]
    pub fn kept(&self) -> &[&str] {
        &self.kept
    }
}

/// Place one file at `dest`: keep without a write when a
/// case-insensitive name or short-name match already holds
/// byte-identical content, refuse naming the file when it holds
/// different bytes, else write `bytes`. `IO.SYS` passes
/// `contiguous` for the `allocate_contiguous` + `link_file` path;
/// the rest use `create_file`. Returns the byte count and records
/// kept files in `kept`.
fn place(
    fat: &mut Fat32,
    dest: &str,
    name: &'static str,
    bytes: &[u8],
    contiguous: bool,
    kept: &mut Vec<&'static str>,
) -> Result<u64> {
    let len = u64::try_from(bytes.len()).map_err(|_| {
        CoreError::invalid(format!("msdos file '{name}' is longer than u64: refusing"))
    })?;
    let present = fat.list_dir("/")?.iter().any(|entry| {
        entry.name.eq_ignore_ascii_case(name) || entry.short_name.eq_ignore_ascii_case(name)
    });
    if present {
        let back = fat.read_file(dest)?;
        if back.as_slice() == bytes {
            kept.push(name);
            return Ok(len);
        }
        return Err(CoreError::invalid(format!(
            "msdos file '{name}' already present at '/' differs from the supplied copy: refusing to overwrite it"
        )));
    }
    if contiguous {
        let (first, _) = fat.allocate_contiguous(len)?;
        fat.link_file(dest, first, len)?;
    } else {
        fat.create_file(dest, len)?;
    }
    fat.write_at(dest, 0, bytes)?;
    Ok(len)
}

/// Write the MS-DOS files at the volume root: patched `IO.SYS`
/// first (one contiguous run, first root entry — what MS-DOS reads
/// at boot), then `MSDOS.SYS`, then patched `COMMAND.COM`.
///
/// The first-entry guarantee assumes an empty root: [`install`]
/// appends, so on a volume that already holds another entry `IO.SYS`
/// takes a later slot, and a caller placing MS-DOS after other files
/// must not rely on it.
///
/// Each file follows the keep-if-identical policy: an existing entry
/// matching by case-insensitive name or short name counts as kept —
/// and nothing is written — when its bytes equal the bytes that
/// would be written; differing bytes refuse naming the file, since
/// silently keeping a foreign DOS would boot it. A failure between
/// files leaves a partial set behind (the torn-state window), but
/// nothing writes a boot record, so nothing becomes half-bootable.
/// Does not flush: the caller owns the flush.
pub fn install(fat: &mut Fat32, files: &MsDosFiles) -> Result<Installed> {
    let io = patch_io_sys(files.io_sys());
    let command = patch_command_com(files.command_com());
    let mut kept: Vec<&'static str> = Vec::new();
    let io_sys = place(fat, IO_SYS_PATH, IO_SYS, io.bytes(), true, &mut kept)?;
    let msdos_sys = place(
        fat,
        MSDOS_SYS_PATH,
        MSDOS_SYS,
        files.msdos_sys(),
        false,
        &mut kept,
    )?;
    let command_com = place(
        fat,
        COMMAND_COM_PATH,
        COMMAND_COM,
        command.bytes(),
        false,
        &mut kept,
    )?;
    Ok(Installed {
        io_sys,
        msdos_sys,
        command_com,
        io_sys_patch: io.state(),
        command_com_patch: command.state(),
        kept,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result as TestResult;
    use crate::fs::Volume;
    use crate::fs::fat32::format::FormatOptions;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Synthetic `IO.SYS`-shaped input at the exact expected size with
    /// the reference signature planted: stand-in bytes for layout
    /// tests — synthetic, not real DOS bytes.
    fn io_sys_input() -> Vec<u8> {
        let mut bytes: Vec<u8> = (0..IO_SYS_BYTES)
            .map(|index| ((index * 7 + 3) % 251) as u8)
            .collect();
        let end = IO_SYS_SIGNATURE_OFFSET + IO_SYS_SIGNATURE.len();
        bytes[IO_SYS_SIGNATURE_OFFSET..end].copy_from_slice(&IO_SYS_SIGNATURE);
        bytes
    }

    /// Synthetic `COMMAND.COM`-shaped input at the exact expected size
    /// with the reference signature planted: stand-in bytes for
    /// layout tests — synthetic, not real DOS bytes.
    fn command_com_input() -> Vec<u8> {
        let mut bytes: Vec<u8> = (0..COMMAND_COM_BYTES)
            .map(|index| ((index * 5 + 1) % 251) as u8)
            .collect();
        let end = COMMAND_COM_SIGNATURE_OFFSET + COMMAND_COM_SIGNATURE.len();
        bytes[COMMAND_COM_SIGNATURE_OFFSET..end].copy_from_slice(&COMMAND_COM_SIGNATURE);
        bytes
    }

    /// A caller-supplied set whose patches both apply.
    fn supplied_files() -> MsDosFiles {
        MsDosFiles {
            io_sys: io_sys_input(),
            msdos_sys: vec![0xABu8; 2048],
            command_com: command_com_input(),
        }
    }

    /// Write `name` with `bytes` into `dir`.
    fn write_named(dir: &Path, name: &str, bytes: &[u8]) {
        std::fs::write(dir.join(name), bytes).expect("the fixture writes");
    }

    /// A [`Volume`] over shared bytes, the same shim the kolibri and
    /// syslinux installer tests use: `Fat32` keeps its store private,
    /// so the tests watch the image through the shared handle.
    #[derive(Debug, Clone)]
    struct SharedVolume {
        bytes: Rc<RefCell<Vec<u8>>>,
    }

    impl SharedVolume {
        fn blank(len: u64) -> Self {
            let size = usize::try_from(len).expect("the ram size fits usize");
            Self {
                bytes: Rc::new(RefCell::new(vec![0u8; size])),
            }
        }
    }

    impl Volume for SharedVolume {
        fn total_bytes(&self) -> u64 {
            self.bytes.borrow().len() as u64
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> TestResult<()> {
            let borrowed = self.bytes.borrow();
            let start = usize::try_from(offset).expect("the test offset fits usize");
            let end = start.checked_add(buf.len()).expect("the test window fits");
            let window = borrowed.get(start..end).expect("the test read fits");
            buf.copy_from_slice(window);
            Ok(())
        }

        fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> TestResult<()> {
            let mut borrowed = self.bytes.borrow_mut();
            let start = usize::try_from(offset).expect("the test offset fits usize");
            let end = start.checked_add(buf.len()).expect("the test write fits");
            let window = borrowed.get_mut(start..end).expect("the test write fits");
            window.copy_from_slice(buf);
            Ok(())
        }
    }

    /// A freshly formatted 64 MiB volume plus the shared handle that
    /// still observes its bytes.
    fn formatted() -> (SharedVolume, Fat32) {
        let backing = SharedVolume::blank(64 * 1024 * 1024);
        let fat = Fat32::format(
            Box::new(backing.clone()),
            &FormatOptions {
                volume_id: 0x1234_5678,
                ..Default::default()
            },
        )
        .expect("the volume formats");
        (backing, fat)
    }

    /// Pin the reference sizes, offsets and signature bytes, and that
    /// a patch result keeps its input length.
    fn assert_patch_applied(patched: &Patched, input: &[u8], patch_offset: usize) {
        assert_eq!(
            patched.state(),
            PatchState::Applied,
            "the planted signature patches"
        );
        assert_eq!(
            patched.bytes().len(),
            input.len(),
            "the patched length equals the input length"
        );
        let out = patched.bytes();
        assert_eq!(
            out[patch_offset], 0xEB,
            "the patch offset carries 0xEB after the patch"
        );
        let mut differing = 0usize;
        for (index, (&was, &is)) in input.iter().zip(out.iter()).enumerate() {
            if was != is {
                differing += 1;
                assert_eq!(
                    index, patch_offset,
                    "the only differing byte is the patch offset"
                );
            }
        }
        assert_eq!(differing, 1, "exactly one byte differs from the input");
    }

    #[test]
    fn constants_pin_the_reference_numbers() {
        assert_eq!(IO_SYS, "IO.SYS", "the bios name");
        assert_eq!(MSDOS_SYS, "MSDOS.SYS", "the kernel name");
        assert_eq!(COMMAND_COM, "COMMAND.COM", "the shell name");
        assert_eq!(IO_SYS_BYTES, 116_736, "the IO.SYS size");
        assert_eq!(IO_SYS_BYTES, 0x1C800, "the IO.SYS size in hex");
        assert_eq!(COMMAND_COM_BYTES, 93_040, "the COMMAND.COM size");
        assert_eq!(COMMAND_COM_BYTES, 0x16B70, "the COMMAND.COM size in hex");
        assert_eq!(IO_SYS_SIGNATURE_OFFSET, 0x3A8, "the IO.SYS window");
        assert_eq!(IO_SYS_PATCH_OFFSET, 0x3AA, "the IO.SYS patch byte");
        assert_eq!(
            IO_SYS_SIGNATURE,
            [0xFA, 0x80, 0x75, 0x09, 0x8D, 0xB6, 0x99, 0x00],
            "the IO.SYS window bytes"
        );
        assert_eq!(IO_SYS_PATCHED, 0xEB, "the IO.SYS patch byte");
        assert_eq!(COMMAND_COM_SIGNATURE_OFFSET, 0x650C, "the shell window");
        assert_eq!(COMMAND_COM_PATCH_OFFSET, 0x6510, "the shell patch byte");
        assert_eq!(
            COMMAND_COM_SIGNATURE,
            [0x15, 0x80, 0xFA, 0x03, 0x75, 0x10, 0xB8, 0x0E],
            "the shell window bytes"
        );
        assert_eq!(COMMAND_COM_PATCHED, 0xEB, "the shell patch byte");
        assert_eq!(MAX_FILE_BYTES, 8 * 1024 * 1024, "the read cap is 8 MiB");
    }

    #[test]
    fn patch_io_sys_applies_at_the_documented_offset() {
        let input = io_sys_input();
        assert_patch_applied(&patch_io_sys(&input), &input, IO_SYS_PATCH_OFFSET);
    }

    #[test]
    fn patch_command_com_applies_at_the_documented_offset() {
        let input = command_com_input();
        assert_patch_applied(&patch_command_com(&input), &input, COMMAND_COM_PATCH_OFFSET);
    }

    #[test]
    fn size_mismatch_returns_the_bytes_untouched() {
        let short = vec![0xABu8; 1024];
        for patched in [patch_io_sys(&short), patch_command_com(&short)] {
            assert_eq!(
                patched.state(),
                PatchState::UnexpectedSize { observed: 1024 },
                "a short input reports its observed length"
            );
            assert_eq!(
                patched.bytes(),
                &short,
                "a size miss returns the bytes unchanged"
            );
            assert_eq!(
                patched.state().note(),
                Some("  unexpected file size"),
                "the size miss replays the reference log text"
            );
        }
        let long = vec![0xCDu8; COMMAND_COM_BYTES + 1];
        let patched = patch_command_com(&long);
        assert_eq!(
            patched.state(),
            PatchState::UnexpectedSize {
                observed: (COMMAND_COM_BYTES + 1) as u64,
            },
            "a long input reports its observed length"
        );
        assert_eq!(
            patched.bytes(),
            &long,
            "a long input returns the bytes unchanged"
        );
    }

    #[test]
    fn signature_mismatch_returns_the_bytes_untouched() {
        // Right size, one signature byte wrong: the length check passes
        // and the window check misses.
        let mut input = io_sys_input();
        input[IO_SYS_SIGNATURE_OFFSET] ^= 0x01;
        let patched = patch_io_sys(&input);
        assert_eq!(
            patched.state(),
            PatchState::UnexpectedSignature,
            "a wrong window byte misses the signature"
        );
        assert_eq!(
            patched.bytes(),
            &input,
            "a signature miss returns the bytes unchanged"
        );
        assert_eq!(
            patched.state().note(),
            Some("  unexpected binary data"),
            "the signature miss replays the reference log text"
        );
        let mut shell = command_com_input();
        let last = COMMAND_COM_SIGNATURE_OFFSET + COMMAND_COM_SIGNATURE.len() - 1;
        shell[last] ^= 0x01;
        let patched = patch_command_com(&shell);
        assert_eq!(
            patched.state(),
            PatchState::UnexpectedSignature,
            "a wrong tail byte misses the shell signature"
        );
        assert_eq!(
            patched.bytes(),
            &shell,
            "a shell signature miss returns the bytes unchanged"
        );
    }

    #[test]
    fn patched_length_always_equals_the_input_length() {
        // Whatever the input shape — empty, short, exact, long — the
        // patch never grows or shrinks the bytes.
        for len in [0usize, 1, 1024, IO_SYS_BYTES, IO_SYS_BYTES + 64] {
            let input = vec![0x55u8; len];
            assert_eq!(
                patch_io_sys(&input).bytes().len(),
                len,
                "the IO.SYS patch keeps a {len} byte input whole"
            );
        }
        for len in [0usize, 1, 1024, COMMAND_COM_BYTES, COMMAND_COM_BYTES + 64] {
            let input = vec![0x55u8; len];
            assert_eq!(
                patch_command_com(&input).bytes().len(),
                len,
                "the shell patch keeps a {len} byte input whole"
            );
        }
        assert_eq!(
            patch_io_sys(&io_sys_input()).state().note(),
            None,
            "an applied patch carries no log note"
        );
    }

    #[test]
    fn install_writes_three_files_with_io_sys_first_and_contiguous() {
        let (backing, mut fat) = formatted();
        let files = supplied_files();
        let done = install(&mut fat, &files).expect("the install runs");
        assert_eq!(
            done.io_sys(),
            IO_SYS_BYTES as u64,
            "the report counts the IO.SYS bytes"
        );
        assert_eq!(
            done.msdos_sys(),
            2048,
            "the report counts the MSDOS.SYS bytes"
        );
        assert_eq!(
            done.command_com(),
            COMMAND_COM_BYTES as u64,
            "the report counts the COMMAND.COM bytes"
        );
        assert_eq!(
            done.io_sys_patch(),
            PatchState::Applied,
            "the IO.SYS patch lands"
        );
        assert_eq!(
            done.command_com_patch(),
            PatchState::Applied,
            "the shell patch lands"
        );
        assert!(
            done.kept().is_empty(),
            "a fresh install keeps nothing: {:?}",
            done.kept()
        );

        // The root holds the three files, with IO.SYS first.
        let listed = fat.list_dir("/").expect("the root lists");
        let shorts: Vec<&str> = listed
            .iter()
            .map(|entry| entry.short_name.as_str())
            .collect();
        assert_eq!(
            shorts,
            vec!["IO.SYS", "MSDOS.SYS", "COMMAND.COM"],
            "the root lists the three files with IO.SYS first"
        );

        // Each file reads back equal to its patched bytes.
        let back = fat.read_file("/IO.SYS").expect("IO.SYS reads back");
        assert_eq!(
            back,
            patch_io_sys(files.io_sys()).bytes(),
            "IO.SYS is the patched bytes"
        );
        let back = fat.read_file("/MSDOS.SYS").expect("MSDOS.SYS reads back");
        assert_eq!(back, files.msdos_sys(), "MSDOS.SYS is verbatim");
        let back = fat
            .read_file("/COMMAND.COM")
            .expect("COMMAND.COM reads back");
        assert_eq!(
            back,
            patch_command_com(files.command_com()).bytes(),
            "COMMAND.COM is the patched bytes"
        );

        // IO.SYS sits in one contiguous run ending in end-of-chain:
        // walk the first FAT copy straight from the raw image, the
        // way the syslinux installer test pins its stage run. The
        // allocator journals the chain and `install` never flushes,
        // so the caller-side flush below materializes it first.
        fat.flush().expect("the caller-side flush runs");
        let geometry = *fat.geometry();
        let io_entry = listed
            .iter()
            .find(|entry| entry.short_name == "IO.SYS")
            .expect("IO.SYS is listed");
        let cluster_bytes = geometry.cluster_bytes();
        let clusters = (IO_SYS_BYTES as u64).div_ceil(cluster_bytes);
        let count = u32::try_from(clusters).expect("the test run fits u32");
        let fat_start = u64::from(geometry.reserved_sectors) * u64::from(geometry.bytes_per_sector);
        let image = backing.bytes.borrow();
        for offset in 0..count {
            let cluster = io_entry
                .first_cluster
                .checked_add(offset)
                .expect("the test cluster fits");
            let at = usize::try_from(fat_start + u64::from(cluster) * 4)
                .expect("the fat window fits usize");
            let window = image.get(at..at + 4).expect("the fat entry fits");
            let raw = u32::from_le_bytes([window[0], window[1], window[2], window[3]]);
            if offset + 1 < count {
                let next = cluster.checked_add(1).expect("the next cluster fits");
                assert_eq!(
                    raw, next,
                    "cluster {cluster} links to the next cluster, not {raw:#010x}"
                );
            } else {
                assert!(
                    raw >= 0x0FFF_FFF8,
                    "cluster {cluster} closes with end-of-chain, not {raw:#010x}"
                );
            }
        }
    }

    #[test]
    fn install_keeps_identical_bytes() {
        // A second install over identical bytes keeps all three: the
        // copy step legitimately places them first, so nothing writes.
        let (_backing, mut fat) = formatted();
        let files = supplied_files();
        install(&mut fat, &files).expect("the first install runs");
        let again = install(&mut fat, &files).expect("identical bytes are kept");
        assert_eq!(
            again.kept(),
            &["IO.SYS", "MSDOS.SYS", "COMMAND.COM"],
            "the second install reports all three files kept"
        );
        assert_eq!(again.io_sys(), IO_SYS_BYTES as u64, "the kept counts hold");
        let back = fat.read_file("/IO.SYS").expect("the kept file reads back");
        assert_eq!(
            back,
            patch_io_sys(files.io_sys()).bytes(),
            "kept IO.SYS bytes unchanged"
        );
    }

    #[test]
    fn install_refuses_differing_bytes() {
        // A foreign `/COMMAND.COM` refuses naming the file and stays
        // untouched — keeping it would boot a foreign shell.
        let (_backing, mut fat) = formatted();
        let files = supplied_files();
        let foreign = b"foreign-command-bytes".to_vec();
        fat.create_file("/COMMAND.COM", foreign.len() as u64)
            .expect("a foreign file lands first");
        fat.write_at("/COMMAND.COM", 0, &foreign)
            .expect("the foreign write lands");
        let error = install(&mut fat, &files).expect_err("differing bytes refuse");
        let text = error.to_string();
        assert!(text.contains("COMMAND.COM"), "names the file: {text}");
        assert!(text.contains("differs"), "names the conflict: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let back = fat.read_file("/COMMAND.COM").expect("the file still reads");
        assert_eq!(back, foreign, "foreign bytes untouched");
    }

    #[test]
    fn load_reads_three_files_case_insensitively() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        write_named(scratch.path(), "io.sys", b"bios-bytes");
        write_named(scratch.path(), "Msdos.Sys", b"kernel-bytes");
        write_named(scratch.path(), "COMMAND.com", b"shell-bytes");
        let files = MsDosFiles::load(scratch.path()).expect("the load reads");
        assert_eq!(files.io_sys(), b"bios-bytes", "the bios bytes return");
        assert_eq!(
            files.msdos_sys(),
            b"kernel-bytes",
            "the kernel bytes return"
        );
        assert_eq!(
            files.command_com(),
            b"shell-bytes",
            "the shell bytes return"
        );
    }

    #[test]
    fn load_refuses_a_missing_file_by_name() {
        // Only two of the three names: the load refuses naming the
        // missing one and the licensing reason.
        let scratch = tempfile::tempdir().expect("a scratch directory");
        write_named(scratch.path(), "IO.SYS", b"bios-bytes");
        write_named(scratch.path(), "MSDOS.SYS", b"kernel-bytes");
        let error = MsDosFiles::load(scratch.path()).expect_err("a missing file refuses");
        let text = error.to_string();
        assert!(
            text.contains("COMMAND.COM"),
            "names the missing file: {text}"
        );
        assert!(
            text.contains("bundled"),
            "names the licensing reason: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }

    #[test]
    fn load_refuses_a_non_regular_file() {
        // A directory named `IO.SYS` is not a file to read: the load
        // refuses naming it instead of failing on the read.
        let scratch = tempfile::tempdir().expect("a scratch directory");
        std::fs::create_dir(scratch.path().join("IO.SYS")).expect("the directory lands");
        write_named(scratch.path(), "MSDOS.SYS", b"kernel-bytes");
        write_named(scratch.path(), "COMMAND.COM", b"shell-bytes");
        let error = MsDosFiles::load(scratch.path()).expect_err("a directory refuses");
        let text = error.to_string();
        assert!(text.contains("IO.SYS"), "names the path: {text}");
        assert!(text.contains("regular file"), "names the problem: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }

    #[test]
    fn load_refuses_an_oversize_file_with_both_sizes() {
        // One byte past the 8 MiB cap: the load refuses naming the
        // file, the observed length and the cap.
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let big = vec![0xABu8; (MAX_FILE_BYTES + 1) as usize];
        write_named(scratch.path(), "IO.SYS", &big);
        write_named(scratch.path(), "MSDOS.SYS", b"kernel-bytes");
        write_named(scratch.path(), "COMMAND.COM", b"shell-bytes");
        let error = MsDosFiles::load(scratch.path()).expect_err("an oversize file refuses");
        let text = error.to_string();
        assert!(text.contains("IO.SYS"), "names the file: {text}");
        assert!(
            text.contains(&(MAX_FILE_BYTES + 1).to_string()),
            "names the observed length: {text}"
        );
        assert!(
            text.contains(&MAX_FILE_BYTES.to_string()),
            "names the cap: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }

    #[test]
    fn load_propagates_io_errors_with_the_path() {
        // A missing directory is a real I/O error, not a missing-file
        // refusal: it keeps the Io shape and names the path.
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let missing = scratch.path().join("no-such-dir");
        let error = MsDosFiles::load(&missing).expect_err("a missing directory refuses");
        assert!(
            matches!(error, CoreError::Io { .. }),
            "the I/O error keeps its shape: {error}"
        );
        let text = error.to_string();
        assert!(
            text.contains(&missing.display().to_string()),
            "names the path: {text}"
        );
    }

    #[test]
    fn cluster_size_refusal_carries_the_reference_sentence() {
        let error = check_cluster_size(65_536).expect_err("a 64 KiB cluster refuses");
        assert_eq!(
            error.to_string(),
            "invalid input: MS-DOS cannot boot from a drive using a 64 kilobytes Cluster size.",
            "the refusal is the verbatim MSG_110 sentence under the standard prefix"
        );
        assert!(error.to_string().is_ascii(), "the refusal stays ASCII");
        assert!(
            check_cluster_size(65_535).is_ok(),
            "one byte under the limit passes"
        );
        assert!(
            check_cluster_size(32_768).is_ok(),
            "a 32 KiB cluster passes"
        );
    }

    #[test]
    fn installed_image_is_fsck_clean() {
        // Acceptance over the real checker: the image dumps to a
        // tempfile and `fsck.fat -n` (read-only) must exit 0. The tool
        // resolves through `PATH`; when it is absent the test skips.
        // No flush inside `install` itself: the caller-side flush
        // below publishes the allocation to the image.
        let (backing, mut fat) = formatted();
        install(&mut fat, &supplied_files()).expect("the install runs");
        fat.flush().expect("the caller-side flush runs");
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join("msdos.img");
        std::fs::write(&image, backing.bytes.borrow().as_slice()).expect("the image dumps");
        let output = match std::process::Command::new("fsck.fat")
            .arg("-n")
            .arg(&image)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                eprintln!("skip: the fsck acceptance needs fsck.fat on PATH ({error})");
                return;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "fsck.fat -n exits 0 after the msdos write ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }
}
