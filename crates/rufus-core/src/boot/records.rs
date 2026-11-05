//! FAT32 boot records for the FreeDOS and KolibriOS sticks: the two
//! ms-sys payloads Rufus writes through `write_fat_32_fd_br` and
//! `write_fat_32_kos_br` (`src/ms-sys/fat32.c`), called from
//! `src/format.c:1033` (FreeDOS, with `bKeepLabel = 0`) and
//! `src/format.c:1037` (KolibriOS). `FUN_140075d80` carries the same
//! KolibriOS record inlined rather than calling ms-sys.
//!
//! Provenance, stated exactly so the transcription stays checkable.
//! Both bodies below were transcribed programmatically from the
//! readable upstream ms-sys headers (a scratch script parsed the hex
//! tokens between the braces — nothing was retyped by hand): the
//! FreeDOS body is exactly the first 430 bytes of
//! `src/ms-sys/inc/br_fat32fd_0x52.h` (the boot code at `0x52..0x200`;
//! the header's remaining 488 bytes are a blank FSInfo sector which
//! this module deliberately does not ship — see
//! [`freedos`](super::freedos)), and the KolibriOS body is the 430
//! bytes of `src/ms-sys/inc/br_fat32kos_0x52.h`. The 11-byte head is
//! `src/ms-sys/inc/br_fat32_0x0.h` (`EB 58 90` plus `MSWIN4.1`). The
//! FreeDOS code itself is the ANI (substring gmbh) bootstrap named in
//! that header's comment, adapted for FreeDOS; the KolibriOS code
//! carries the `MTLD_F32` loader name. ms-sys is GPL-2.0-or-later,
//! which the Free Software Foundation lists as compatible with this
//! project's GPL-3.0-or-later. The reconstructed sector (`head` at
//! `0x0`, `NO NAME    ` at `0x47`, KolibriOS body at `0x52`) was
//! verified byte-identical — 0 differing bytes — against the record
//! Rufus generates in `FUN_140075d80`, so the ms-sys source is the
//! authoritative transcription source for both records; no bytes were
//! carved out of the unpacked exe.
//!
//! What the builders emit, and what they do not. [`freedos_fat32`]
//! and [`kolibri_fat32`] assemble a 512-byte sector-0 image: the head
//! at `0x0`, the body at `0x52`, `55 AA` at `0x1FE` (both bodies
//! already end in `55 AA` at their tail, matching the reference
//! byte for byte). Bytes `0x0B..0x5A` — the whole BPB/EBPB window,
//! including the 11-char label slot at `0x47..0x52` — are placeholder
//! zeros: [`write`] never puts them on disk verbatim but routes the
//! record through
//! [`Fat32::write_boot_code`](crate::fs::fat32::Fat32::write_boot_code),
//! whose [`graft`](crate::fs::fat32::bpb::graft_boot_code) keeps the
//! volume's own `0x0B..0x5A` geometry (the user's volume label
//! survives instead of being replaced with `NO NAME    `) and takes
//! only the record's `0x00..0x0B` entry and `0x5A..0x1FE` code. Even
//! the body's own first 8 bytes (`FAT32   ` at `0x52..0x5A`) are
//! discarded by that graft — they describe the build machine's
//! volume, never this one.
//!
//! Sector-0-only rule. The FreeDOS reference additionally rewrites
//! sector 1 from its header's FSInfo image and zeroes sector 2,
//! purely so 1024/2048-byte-sector media see a boot signature at
//! `0x3FE`/`0x5FE` (that is what ms-sys `is_fat_32_br` checks) — but
//! it leaves the 8 FSInfo count bytes at absolute `0x3E8..0x3F0`
//! unwritten, so the formatter's real free-cluster counts survive
//! there. Our volumes use 512-byte sectors and the BIOS loads only
//! sector 0 — so [`write`] preserves sectors 1 and 2 instead of
//! rewriting them (see [`freedos`](super::freedos) for the full
//! reasoning).
//!
//! The FreeDOS FAT16 record is out of scope: this project formats
//! FAT32 only (see `fs/fat32/geometry.rs`, which refuses FAT16
//! territory), so only the FAT32 records are transcribed here.
//!
//! All error and assertion text is ASCII.

use crate::error::Result;
use crate::fs::fat32::Fat32;
use crate::fs::fat32::put_bytes;

/// The shared 11-byte record head (`br_fat32_0x0.h`): `EB 58 90` plus
/// the `MSWIN4.1` OEM name. The jump lands at `0x5A`, the first code
/// byte past the `FAT32   ` type string.
pub const FAT32_HEAD: [u8; 11] = [
    0xEB, 0x58, 0x90, 0x4D, 0x53, 0x57, 0x49, 0x4E, 0x34, 0x2E, 0x31,
];

/// The FreeDOS FAT32 boot code: exactly the first 430 bytes of
/// ms-sys `br_fat32fd_0x52.h` (`write_fat_32_fd_br`,
/// `src/ms-sys/fat32.c:101-125`), the ANI bootstrap adapted for
/// FreeDOS. The header's remaining 488 bytes — a blank FSInfo sector
/// (`RRaA` at absolute `0x200`, `rrAa` at `0x3E4`) — are not shipped
/// (see the module docs). Carries `FAT32   ` at body offset 0, code
/// from offset 8, the `Loading FreeDOS` / `No KERNEL  SYS` strings
/// (`FreeDOS` at body offset 375) and `55 AA` at body offset 428.
pub const FREEDOS_FAT32_BODY: &[u8] = &FREEDOS_FAT32_BODY_ARR;

/// The array behind [`FREEDOS_FAT32_BODY`]: the fixed size is the
/// transcription contract (exactly the 430 code bytes), so the
/// compiler — not just the digest test — rejects a miscount.
const FREEDOS_FAT32_BODY_ARR: [u8; BODY_BYTES] = [
    0x46, 0x41, 0x54, 0x33, 0x32, 0x20, 0x20, 0x20, 0xFC, 0xFA, 0x29, 0xC0, 0x8E, 0xD8, 0xBD, 0x00,
    0x7C, 0xB8, 0xE0, 0x1F, 0x8E, 0xC0, 0x89, 0xEE, 0x89, 0xEF, 0xB9, 0x00, 0x01, 0xF3, 0xA5, 0xEA,
    0x7A, 0x7C, 0xE0, 0x1F, 0x00, 0x00, 0x60, 0x00, 0x8E, 0xD8, 0x8E, 0xD0, 0x8D, 0x66, 0xE0, 0xFB,
    0x88, 0x56, 0x40, 0xBE, 0xC1, 0x7D, 0xE8, 0xF4, 0x00, 0x66, 0x31, 0xC0, 0x66, 0x89, 0x46, 0x44,
    0x8B, 0x46, 0x0E, 0x66, 0x03, 0x46, 0x1C, 0x66, 0x89, 0x46, 0x48, 0x66, 0x89, 0x46, 0x4C, 0x66,
    0x8B, 0x46, 0x10, 0x66, 0xF7, 0x6E, 0x24, 0x66, 0x01, 0x46, 0x4C, 0xB8, 0x00, 0x02, 0x3B, 0x46,
    0x0B, 0x74, 0x08, 0x01, 0xC0, 0xFF, 0x06, 0x34, 0x7D, 0xEB, 0xF3, 0x66, 0x8B, 0x46, 0x2C, 0x66,
    0x50, 0xE8, 0x94, 0x00, 0x72, 0x4D, 0xC4, 0x5E, 0x76, 0xE8, 0xB7, 0x00, 0x31, 0xFF, 0xB9, 0x0B,
    0x00, 0xBE, 0xF1, 0x7D, 0xF3, 0xA6, 0x74, 0x15, 0x83, 0xC7, 0x20, 0x83, 0xE7, 0xE0, 0x3B, 0x7E,
    0x0B, 0x75, 0xEB, 0x4A, 0x75, 0xE0, 0x66, 0x58, 0xE8, 0x34, 0x00, 0xEB, 0xD2, 0x26, 0xFF, 0x75,
    0x09, 0x26, 0xFF, 0x75, 0x0F, 0x66, 0x58, 0x29, 0xDB, 0x66, 0x50, 0xE8, 0x5A, 0x00, 0x72, 0x0D,
    0xE8, 0x80, 0x00, 0x4A, 0x75, 0xFA, 0x66, 0x58, 0xE8, 0x14, 0x00, 0xEB, 0xEC, 0x8A, 0x5E, 0x40,
    0xFF, 0x6E, 0x76, 0xBE, 0xEE, 0x7D, 0xE8, 0x64, 0x00, 0x30, 0xE4, 0xCD, 0x16, 0xCD, 0x19, 0x06,
    0x57, 0x53, 0x89, 0xC7, 0xC1, 0xE7, 0x02, 0x50, 0x8B, 0x46, 0x0B, 0x48, 0x21, 0xC7, 0x58, 0x66,
    0xC1, 0xE8, 0x07, 0x66, 0x03, 0x46, 0x48, 0xBB, 0x00, 0x20, 0x8E, 0xC3, 0x29, 0xDB, 0x66, 0x3B,
    0x46, 0x44, 0x74, 0x07, 0x66, 0x89, 0x46, 0x44, 0xE8, 0x38, 0x00, 0x26, 0x80, 0x65, 0x03, 0x0F,
    0x26, 0x66, 0x8B, 0x05, 0x5B, 0x5F, 0x07, 0xC3, 0x66, 0x3D, 0xF8, 0xFF, 0xFF, 0x0F, 0x73, 0x15,
    0x66, 0x48, 0x66, 0x48, 0x66, 0x0F, 0xB6, 0x56, 0x0D, 0x66, 0x52, 0x66, 0xF7, 0xE2, 0x66, 0x5A,
    0x66, 0x03, 0x46, 0x4C, 0xC3, 0xF9, 0xC3, 0x31, 0xDB, 0xB4, 0x0E, 0xCD, 0x10, 0xAC, 0x3C, 0x00,
    0x75, 0xF5, 0xC3, 0x52, 0x56, 0x57, 0x66, 0x50, 0x89, 0xE7, 0x6A, 0x00, 0x6A, 0x00, 0x66, 0x50,
    0x06, 0x53, 0x6A, 0x01, 0x6A, 0x10, 0x89, 0xE6, 0x8A, 0x56, 0x40, 0xB4, 0x42, 0xCD, 0x13, 0x89,
    0xFC, 0x66, 0x58, 0x73, 0x08, 0x50, 0x30, 0xE4, 0xCD, 0x13, 0x58, 0xEB, 0xD9, 0x66, 0x40, 0x03,
    0x5E, 0x0B, 0x73, 0x07, 0x8C, 0xC2, 0x80, 0xC6, 0x10, 0x8E, 0xC2, 0x5F, 0x5E, 0x5A, 0xC3, 0x4C,
    0x6F, 0x61, 0x64, 0x69, 0x6E, 0x67, 0x20, 0x46, 0x72, 0x65, 0x65, 0x44, 0x4F, 0x53, 0x20, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x6F, 0x20, 0x4B,
    0x45, 0x52, 0x4E, 0x45, 0x4C, 0x20, 0x20, 0x53, 0x59, 0x53, 0x00, 0x00, 0x55, 0xAA,
];

/// The KolibriOS FAT32 boot code: the 430 bytes of ms-sys
/// `br_fat32kos_0x52.h` (`write_fat_32_kos_br`,
/// `src/ms-sys/fat32.c:282-300`), the record Rufus writes in
/// `FUN_140075d80`. Carries `FAT32   ` at body offset 0, code from
/// offset 8, the `Cannot find file MTLD_F32` / `Disk read error` /
/// `Bad cluster` strings (`MTLD_F32` at body offset 377) and `55 AA`
/// at body offset 428.
pub const KOLIBRI_FAT32_BODY: &[u8] = &KOLIBRI_FAT32_BODY_ARR;

/// The array behind [`KOLIBRI_FAT32_BODY`]: the fixed size is the
/// transcription contract (exactly the 430 header bytes), so the
/// compiler — not just the digest test — rejects a miscount.
const KOLIBRI_FAT32_BODY_ARR: [u8; BODY_BYTES] = [
    0x46, 0x41, 0x54, 0x33, 0x32, 0x20, 0x20, 0x20, 0x80, 0x3C, 0x80, 0x75, 0x09, 0x66, 0x8B, 0x44,
    0x08, 0x2E, 0x66, 0xA3, 0x1C, 0x7C, 0x66, 0x31, 0xC0, 0x8E, 0xD8, 0x8E, 0xD0, 0xBC, 0x00, 0x7C,
    0x89, 0xE5, 0x88, 0x16, 0x08, 0x7A, 0xFC, 0xFB, 0x68, 0x00, 0x08, 0x07, 0x66, 0x0F, 0xB7, 0x5E,
    0x0E, 0x66, 0x89, 0x1E, 0x00, 0x7A, 0x8A, 0x46, 0x10, 0x66, 0xF7, 0x66, 0x24, 0x66, 0x01, 0xD8,
    0x66, 0x0F, 0xB6, 0x5E, 0x0D, 0x01, 0xDB, 0x66, 0x29, 0xD8, 0x66, 0xA3, 0x04, 0x7A, 0x66, 0x8B,
    0x46, 0x2C, 0x66, 0x25, 0xFF, 0xFF, 0xFF, 0x0F, 0x31, 0xDB, 0x89, 0xDF, 0x66, 0x50, 0xE8, 0x62,
    0x00, 0x0F, 0xB6, 0x4E, 0x0D, 0xC1, 0xE1, 0x04, 0x26, 0x80, 0x3D, 0x00, 0x74, 0x4D, 0x51, 0x57,
    0xB9, 0x0B, 0x00, 0xBE, 0xCB, 0x7D, 0xF3, 0xA6, 0x5F, 0x59, 0x74, 0x0E, 0x83, 0xC7, 0x20, 0xE2,
    0xE7, 0x66, 0x58, 0xE8, 0x8D, 0x00, 0x73, 0x33, 0x72, 0xCE, 0x66, 0x58, 0x26, 0x8B, 0x45, 0x14,
    0x25, 0xFF, 0x0F, 0x66, 0xC1, 0xE0, 0x10, 0x26, 0x8B, 0x45, 0x1A, 0x31, 0xDB, 0x66, 0x50, 0xE8,
    0x21, 0x00, 0x8C, 0xC0, 0x0F, 0xB6, 0x4E, 0x0D, 0xC1, 0xE1, 0x05, 0x01, 0xC8, 0x8E, 0xC0, 0x66,
    0x58, 0xE8, 0x5F, 0x00, 0x72, 0xE5, 0xEA, 0x00, 0x80, 0x00, 0x00, 0xBE, 0xBA, 0x7D, 0xE8, 0x98,
    0x00, 0xEB, 0xFE, 0x66, 0x0F, 0xB6, 0x4E, 0x0D, 0x66, 0xF7, 0xE1, 0x66, 0x03, 0x06, 0x04, 0x7A,
    0x66, 0x03, 0x46, 0x1C, 0x06, 0x66, 0x60, 0x6A, 0x00, 0x6A, 0x00, 0x66, 0x50, 0x06, 0x53, 0x83,
    0xE9, 0x7F, 0x19, 0xC0, 0x21, 0xC8, 0x83, 0xC0, 0x7F, 0x50, 0xC1, 0xE0, 0x05, 0x8C, 0xC1, 0x01,
    0xC1, 0x8E, 0xC1, 0x6A, 0x10, 0xB8, 0x00, 0x42, 0x8A, 0x16, 0x08, 0x7A, 0x89, 0xE6, 0xCD, 0x13,
    0xBE, 0xD9, 0x7D, 0x72, 0xB9, 0x61, 0x66, 0x61, 0x66, 0x83, 0xC0, 0x7F, 0x83, 0xE9, 0x7F, 0x77,
    0xC4, 0x07, 0xC3, 0x06, 0x1E, 0x07, 0xBB, 0x00, 0x7E, 0x66, 0x50, 0x66, 0xC1, 0xE8, 0x07, 0x66,
    0x3B, 0x06, 0xF9, 0x7D, 0x74, 0x0F, 0x66, 0xA3, 0xF9, 0x7D, 0x66, 0x03, 0x06, 0x00, 0x7A, 0xB9,
    0x01, 0x00, 0xE8, 0x9B, 0xFF, 0x66, 0x58, 0x66, 0x83, 0xE0, 0x7F, 0x67, 0x66, 0x8B, 0x04, 0x85,
    0x00, 0x7E, 0x00, 0x00, 0x66, 0x25, 0xFF, 0xFF, 0xFF, 0x0F, 0x66, 0x3D, 0xF7, 0xFF, 0xFF, 0x0F,
    0xBE, 0xEB, 0x7D, 0x0F, 0x84, 0x67, 0xFF, 0x07, 0xC3, 0xAC, 0x84, 0xC0, 0x74, 0x09, 0xB4, 0x0E,
    0xBB, 0x07, 0x00, 0xCD, 0x10, 0xEB, 0xF2, 0xC3, 0x43, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x66,
    0x69, 0x6E, 0x64, 0x20, 0x66, 0x69, 0x6C, 0x65, 0x20, 0x4D, 0x54, 0x4C, 0x44, 0x5F, 0x46, 0x33,
    0x32, 0x20, 0x20, 0x20, 0x0D, 0x0A, 0x00, 0x44, 0x69, 0x73, 0x6B, 0x20, 0x72, 0x65, 0x61, 0x64,
    0x20, 0x65, 0x72, 0x72, 0x6F, 0x72, 0x0D, 0x0A, 0x00, 0x42, 0x61, 0x64, 0x20, 0x63, 0x6C, 0x75,
    0x73, 0x74, 0x65, 0x72, 0x0D, 0x0A, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x55, 0xAA,
];

/// Offset of the boot-code body inside the assembled sector: right
/// after the 11-byte head and the 71-byte BPB/EBPB window.
const BODY_OFFSET: usize = 0x52;

/// Length of each boot-code body in bytes (`0x52..0x200`).
const BODY_BYTES: usize = 430;

/// Assemble a 512-byte sector-0 image from `body`: the head at `0x0`,
/// the body at `0x52`, `55 AA` at `0x1FE`, zeros elsewhere.
///
/// Infallible by construction, the same shape as
/// [`bpb::fsinfo_with_counts`](crate::fs::fat32::bpb::fsinfo_with_counts):
/// every offset is a compile-time constant inside the 512-byte
/// buffer, so the [`put_bytes`] results (which exist for totality)
/// cannot miss and are dropped with `ok`. The fixed-size parameter
/// is the length contract: only the two 430-byte arrays above fit, so
/// a miscount fails to compile.
fn assemble(body: &[u8; BODY_BYTES]) -> [u8; 512] {
    let mut out = [0u8; 512];
    put_bytes(&mut out, 0, &FAT32_HEAD).ok();
    put_bytes(&mut out, BODY_OFFSET, body).ok();
    put_bytes(&mut out, 510, &[0x55, 0xAA]).ok();
    out
}

/// The FreeDOS sector-0 image: head plus [`FREEDOS_FAT32_BODY`].
///
/// The `0x0B..0x5A` window is placeholder zeros for the
/// [`write`] graft (see the module docs): pass the result to
/// [`write`], never straight to the volume.
#[must_use]
pub fn freedos_fat32() -> [u8; 512] {
    assemble(&FREEDOS_FAT32_BODY_ARR)
}

/// The KolibriOS sector-0 image: head plus [`KOLIBRI_FAT32_BODY`].
///
/// The `0x0B..0x5A` window is placeholder zeros for the
/// [`write`] graft (see the module docs): pass the result to
/// [`write`], never straight to the volume.
#[must_use]
pub fn kolibri_fat32() -> [u8; 512] {
    assemble(&KOLIBRI_FAT32_BODY_ARR)
}

/// Graft `record` (one of [`freedos_fat32`]/[`kolibri_fat32`]) onto
/// the volume's boot sector.
///
/// Delegates to
/// [`Fat32::write_boot_code`](crate::fs::fat32::Fat32::write_boot_code):
/// the record's `0x00..0x0B` entry and `0x5A..0x1FE` code win, the
/// volume's own `0x0B..0x5A` BPB/EBPB geometry (volume label
/// included) and the `55 AA` tail survive, and sectors 1 (FSInfo)
/// and 2 are never touched. Does not flush: the caller owns the
/// flush, the same convention as the [`kolibri`](super::kolibri) and
/// [`freedos`](super::freedos) installers.
pub fn write(fat: &mut Fat32, record: &[u8; 512]) -> Result<()> {
    fat.write_boot_code(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::Volume;
    use crate::fs::fat32::format::FormatOptions;
    use crate::hash::Algo;
    use crate::hash::hash_reader;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Both pinned bodies, so every structural assertion below runs
    /// over each record and neither transcription can drift silently.
    fn bodies() -> [(&'static str, &'static [u8]); 2] {
        [
            ("freedos", FREEDOS_FAT32_BODY),
            ("kolibri", KOLIBRI_FAT32_BODY),
        ]
    }

    /// Both assembled records, in the same order.
    fn records() -> [(&'static str, [u8; 512]); 2] {
        [("freedos", freedos_fat32()), ("kolibri", kolibri_fat32())]
    }

    #[test]
    fn bodies_are_exactly_430_bytes() {
        // The anti-drift guard for the hand of the transcription: the
        // ms-sys headers name 430 code bytes at `0x52..0x200`, so any
        // dropped or doubled byte fails here.
        for (name, body) in bodies() {
            assert_eq!(
                body.len(),
                BODY_BYTES,
                "the {name} body is exactly the 430 code bytes"
            );
        }
        assert_eq!(BODY_BYTES, 430, "the named constant is 430");
    }

    #[test]
    fn records_carry_head_body_and_signature() {
        // Every assembled record: 512 bytes, the `EB 58 90` jump plus
        // `MSWIN4.1` head, `FAT32   ` at `0x52`, the body verbatim at
        // `0x52..0x200`, and `55 AA` at `0x1FE`.
        for (name, record) in records() {
            assert_eq!(record.len(), 512, "the {name} record is one sector");
            assert_eq!(
                &record[0..3],
                &[0xEB, 0x58, 0x90],
                "the {name} jump enters at 0x5A"
            );
            assert_eq!(&record[3..11], b"MSWIN4.1", "the {name} oem name");
            assert_eq!(&record[0x52..0x5A], b"FAT32   ", "the {name} type string");
            let body = bodies()
                .iter()
                .find(|(label, _)| *label == name)
                .expect("the named body exists")
                .1;
            assert_eq!(
                &record[0x52..0x200],
                body,
                "the {name} body sits verbatim at 0x52"
            );
            assert_eq!(
                &record[0x1FE..0x200],
                &[0x55, 0xAA],
                "the {name} signature closes the sector"
            );
        }
        // The head constant itself pins the same bytes the loop checks
        // per record.
        assert_eq!(
            FAT32_HEAD,
            [
                0xEB, 0x58, 0x90, 0x4D, 0x53, 0x57, 0x49, 0x4E, 0x34, 0x2E, 0x31,
            ],
            "the shared head is EB 58 90 plus MSWIN4.1"
        );
    }

    #[test]
    fn bodies_carry_their_loader_markers() {
        // The one human-readable anchor per body: `FreeDOS` (the
        // `Loading FreeDOS` string at body offset 375) and `MTLD_F32`
        // (the `Cannot find file MTLD_F32` string at body offset 377).
        // A transcription slip that moved code around fails here.
        let at = FREEDOS_FAT32_BODY
            .windows(b"FreeDOS".len())
            .position(|window| window == b"FreeDOS");
        assert_eq!(at, Some(375), "FreeDOS sits at body offset 375");
        let at = KOLIBRI_FAT32_BODY
            .windows(b"MTLD_F32".len())
            .position(|window| window == b"MTLD_F32");
        assert_eq!(at, Some(377), "MTLD_F32 sits at body offset 377");
    }

    #[test]
    fn body_digests_pin_the_transcription() {
        // The transcription guard: the SHA-256 of each 430-byte body,
        // computed from the arrays above. Any flipped, dropped or
        // reordered byte changes the digest and fails here; the values
        // were computed mechanically from the ms-sys headers, never
        // typed.
        for (name, body, want) in [
            (
                "freedos",
                FREEDOS_FAT32_BODY,
                "9181b7c22f3a7e1d0e59f7cbe1066c7bb5b076018c4862a167335b085836bdd5",
            ),
            (
                "kolibri",
                KOLIBRI_FAT32_BODY,
                "671fc1efe3cd6bbe2774e759a113b5a03de14b358c9a00e8ca7d62ecfc939c58",
            ),
        ] {
            assert!(want.is_ascii(), "the pinned digest stays ASCII");
            let actual = hash_reader(Algo::Sha256, body).expect("in-memory bytes hash");
            assert_eq!(actual, want, "the SHA-256 of the {name} body");
        }
    }

    /// A [`Volume`] over shared bytes, the same shim the syslinux and
    /// kolibri installer tests use: `Fat32` keeps its store private,
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

        /// A copy of one 512-byte sector of the image.
        fn sector(&self, index: usize) -> [u8; 512] {
            let borrowed = self.bytes.borrow();
            let start = index.checked_mul(512).expect("the test offset fits");
            let window = borrowed
                .get(start..start + 512)
                .expect("the test sector fits");
            let mut sector = [0u8; 512];
            sector.copy_from_slice(window);
            sector
        }
    }

    impl Volume for SharedVolume {
        fn total_bytes(&self) -> u64 {
            self.bytes.borrow().len() as u64
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            let borrowed = self.bytes.borrow();
            let start = usize::try_from(offset).expect("the test offset fits usize");
            let end = start.checked_add(buf.len()).expect("the test window fits");
            let window = borrowed.get(start..end).expect("the test read fits");
            buf.copy_from_slice(window);
            Ok(())
        }

        fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
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

    /// The full graft proof for `record` through [`write`]: the head
    /// and code land, the whole `0x0B..0x5A` BPB window (label
    /// included) survives byte-identical, the tail closes, sectors 1
    /// and 2 are untouched, a second write changes nothing, and the
    /// jump really moved off the formatter's own `EB 3C 90`.
    fn proves_write(backing: &SharedVolume, fat: &mut Fat32, name: &str, record: &[u8; 512]) {
        fat.flush().expect("the pre-write flush runs");
        let before = backing.sector(0);
        let before_fsinfo = backing.sector(1);
        let before_second = backing.sector(2);
        write(fat, record).expect("the record writes");
        let after = backing.sector(0);
        assert_eq!(
            &after[0..11],
            &record[0..11],
            "the {name} jump and oem name win"
        );
        assert_eq!(
            &after[11..90],
            &before[11..90],
            "the {name} graft keeps the whole bpb window, label included"
        );
        assert_eq!(
            &after[90..510],
            &record[90..510],
            "the {name} boot code is the payload's"
        );
        assert_eq!(
            &after[510..512],
            &[0x55, 0xAA],
            "the {name} signature closes the sector"
        );
        assert_eq!(
            backing.sector(1),
            before_fsinfo,
            "the {name} write preserves the fsinfo sector"
        );
        assert_eq!(
            backing.sector(2),
            before_second,
            "the {name} write preserves sector 2"
        );
        // The write is real: the formatter's own jump was `EB 3C 90`
        // (landing at `0x3E` over its zeroed code area) and the record
        // moves it to `EB 58 90` (landing at `0x5A`). The OEM name is
        // `MSWIN4.1` on both sides, so the jump — not the OEM — is the
        // discriminator.
        assert_eq!(
            &before[0..3],
            &[0xEB, 0x3C, 0x90],
            "the formatter's own jump"
        );
        assert_eq!(
            &after[0..3],
            &[0xEB, 0x58, 0x90],
            "the {name} jump replaces it"
        );
        // Ordered and idempotent: a second write lands on the same
        // bytes.
        write(fat, record).expect("the second write runs");
        assert_eq!(
            backing.sector(0),
            after,
            "a second {name} write changes nothing"
        );
    }

    #[test]
    fn write_grafts_the_freedos_record() {
        let (backing, mut fat) = formatted();
        let record = freedos_fat32();
        proves_write(&backing, &mut fat, "freedos", &record);
    }

    #[test]
    fn write_grafts_the_kolibri_record() {
        let (backing, mut fat) = formatted();
        let record = kolibri_fat32();
        proves_write(&backing, &mut fat, "kolibri", &record);
    }

    #[test]
    fn written_image_is_fsck_clean() {
        // Acceptance over the real checker: the image dumps to a
        // tempfile and `fsck.fat -n` (read-only) must exit 0. The tool
        // resolves through `PATH`; when it is absent the test skips.
        // No flush inside [`write`] itself: the caller-side flush
        // below publishes the sector to the image.
        let (backing, mut fat) = formatted();
        write(&mut fat, &kolibri_fat32()).expect("the record writes");
        fat.flush().expect("the caller-side flush runs");
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join("records.img");
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
            "fsck.fat -n exits 0 after the record write ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }

    #[test]
    fn messages_stay_ascii() {
        // Every literal below rides an assertion message, so the ASCII
        // rule pins here rather than one formatting call at a time.
        for text in [
            "freedos", "kolibri", "MTLD_F32", "FreeDOS", "FAT32   ", "MSWIN4.1",
        ] {
            assert!(text.is_ascii(), "the marker stays ASCII: {text}");
        }
    }
}
