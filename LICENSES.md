# LICENSES.md — asset licence audit for the 86 resources of Rufus 4.15

Subject of this audit: the 86 payloads extracted verbatim from
`rufus-4.15.exe` (Rufus 4.15.2396), listed in `../example/resources/README.md`
and fingerprinted in `assets/manifest.json` (sizes + SHA-256). Identification
method: static reverse engineering (`../example/ANALYSIS.md`); where the build
manifest is not embedded in the payload, resource names are content-based
inferences. No lawyer was consulted — this is an engineering sanity pass, as
planned in S00.

Baseline: the rewrite is licensed **GPL-3.0-or-later** (proposed decision A1),
and the assets are reused as embedded data (proposed decision A6). Component
licences below use SPDX identifiers.

## Component licences

| Component | SPDX | Role |
|---|---|---|
| Rufus itself (code, dialogs, icons, glyphs, `rufus.loc`, `rufus.com`, setup wrapper) | `GPL-3.0-or-later` | The upstream program we reuse as data. |
| FreeDOS (FreeCOM, CONFIG.SYS template, KEYB, boot stub, keyboard layouts, DOS utilities) | `GPL-2.0-or-later` | DOS boot payloads written to the target. |
| Syslinux 4.07 / 6.04 | `GPL-2.0-or-later` | Bootloader payloads written to the target. |
| GRUB4DOS | `GPL-2.0-or-later` | Legacy boot helper payload. |
| GRUB2 | `GPL-3.0-or-later` | Future bootloader payload for S19 (not part of these 86 resources). |
| UEFI:NTFS (`uefi-ntfs.img`) | `GPL-3.0-or-later` | NTFS UEFI driver payload written to the target. |
| wimlib (not embedded; linked per A5) | `LGPL-3.0-or-later` | C library for WIM/ESD apply. |
| ntfs-3g (`mkntfs`; external tool per A4) | `GPL-2.0-or-later` | Runtime system tool, not shipped in the binary. |
| Microsoft UEFI KEK/DB certificates | public certificate **data** | X.509 blobs used by the Secure Boot analysis. |

## Resource groups

### Icons — `ICON_1..5` + `GRPICON_120` (6 payloads)

What: RT_ICON RGBA icons (256/96/64/48/32/16 px, PNG-compressed inside) and the
RT_GROUP_ICON directory referencing them. Licence: **`GPL-3.0-or-later`**
(Rufus's own icon set). Uncertainty: the per-file size→icon mapping is not
verified element-by-element; irrelevant to licensing.

### Dialogs `101–110` (10 payloads)

What: `DLGTEMPLATEEX` dialog templates (main window, About, message box,
choice, license, log, update policy, check-for-updates, checksums, list).
Licence: **`GPL-3.0-or-later`** (Rufus UI definitions). No uncertainty. On
Linux they are reimplemented in Slint (A7); the templates serve as the
behavioural spec.

### `VERSION_1` (1 payload)

What: `VS_VERSION_INFO` block ("Rufus 4.15.2396", © 2011–2026 Pete Batard,
GPL v3, Akeo Consulting). Licence: **`GPL-3.0-or-later`** (Rufus metadata).
Used only as provenance data; do not copy version strings into our binary.

### `MANIFEST_1` (1 payload)

What: Windows application manifest (`requireAdministrator`, Common-Controls 6,
DPI/long-path/UTF-8 aware). Licence: **`GPL-3.0-or-later`**. Windows-only
metadata, unused at runtime on Linux.

### UI PNG glyphs — RCDATA `121–146` (18 payloads)

What: modern flat toolbar/status glyphs loaded by `ui.c` through
`FindResourceA` + `LockResource` into `ImageList`/GDI+. Licence:
**`GPL-3.0-or-later`** (Rufus artwork). No uncertainty beyond licensing
conservatism: if we reuse them in the Linux GUI (A6/A7), they stay under our
GPLv3 umbrella; if we draw our own glyphs, these payloads are not distributed.

### FreeDOS — RCDATA `300–326` (27 payloads)

What: DOS boot set used by Rufus's FreeDOS target: FreeCOM (300),
`CONFIG.SYS` template (301), a DOS utility (302), the KEYB keyboard driver
(303), a boot-sector/loader stub (304), the 4-part keyboard layout library
(305–308, Jiri Malak / Henrique Peron) and 18 UPX-packed DOS.COM utilities
(309–326). Licence: **`GPL-2.0-or-later`** (FreeDOS family per decision A6).
GPL-2.0-or-later is compatible with our GPLv3-or-later use. Uncertainty: the
exact per-resource names for 300–308 and especially the utilities 309–326 are
content-based inferences from strings/headers, not verified upstream
filenames — **re-verify in S20** (which ports `dos_locale` and owns the FreeDOS
/exFAT extraction path).

### Syslinux — RCDATA `400–404` (5 payloads)

What: Syslinux 4.07 VBR + core (400/401), Syslinux 6.04 VBR + core (402/403),
and the DOS installer `syslinux.com` (404). Licence: **`GPL-2.0-or-later`**
(Syslinux, per decision A6) — compatible with GPLv3 use. Uncertainty: the
4.07/6.04 version pair is inferred from embedded version strings; payload
identity is confirmed by their role in `syslinux.c` (S19). The installer also
patches files on FAT filesystems; Syslinux's own freestanding bits (ldlinux
binaries) are GPLv2+ data/code reused, not absorbed.

### GRUB4DOS — RCDATA `450–452` (3 payloads)

What: `grldr.mbr` (450), `grldr` (451) used for legacy boot on UEFI-only
systems, plus the ANSI-art error screen "ERROR: BIOS/LEGACY BOOT OF
UEFI-ONLY MEDIA" (452). Licence: **`GPL-2.0-or-later`** (GRUB4DOS per decision
A6). Uncertainty: 452 might be a Rufus-authored custom message file for
`grldr` rather than stock GRUB4DOS content (see `manifest.json` notes); either
way the licence is GPL-2.0+ or GPL-3.0+ and the compatibility conclusion is
unchanged — **re-verify against pbatard/rufus in S19**. GRUB2 (GPLv3+) is
relevant for S19 but is not part of this resource set.

### `RCDATA_500` — `rufus.loc` (1 payload)

What: the `pollock v1.0`-generated translation database (v4.14 header), all
languages shipped by Rufus. Licence: **`GPL-3.0-or-later`** (Rufus project
asset; its translations are contributed under the project's terms). Reused
only if A11 (reuse `rufus.loc`) is confirmed. Uncertainty: none for licensing
at audit level; distribution note — the `.loc` must ship complete with the
GPLv3 source offer, unmodified.

### `RCDATA_501` — `rufus.com` console launcher (1 payload)

What: 2 KB PE32 console launcher/"hogger" that re-launches Rufus on the
console command line (parsed by `cregex_parse.c`). Licence:
**`GPL-3.0-or-later`** (Rufus's own code). Linux: not used; the rewrite has a
native `rufus` CLI (S03). Keep only as behavioural reference.

### `RCDATA_502` — `uefi-ntfs.img` (1 payload)

What: 1 MiB FAT12 image (`mkfs.fat`, label `RUFUS_BOOT`) holding the
`uefi-ntfs.efi` NTFS UEFI driver. Licence: **`GPL-3.0-or-later`** (the
UEFI:NTFS project, per decision A6; same author as Rufus). Compatible. No
distribution problem: the whole FAT image ships as data under GPLv3.

### Setup wrapper — RCDATA `503–504` (2 payloads)

What: Windows-only `setup.exe` wrapper (x64 503, ARM64 504) that bypasses
Windows 11 requirement checks during Windows To Go/unattended setup. Licence:
**`GPL-3.0-or-later`** (Rufus's own code, same as the rest of the program).
These are Windows PE assets **written as data to the target drive**; plan
constraint 4 (`PLAN.md` §2) forbids executing them on Linux. No licence issue.

### uefi-md5sum — RCDATA `601–607` (6 payloads)

What: the `uefi-md5sum` EFI checksum application in six architectures
(601 i386, 602 x86-64, 603 ARM Thumb-2, 604 ARM64, 606 RISC-V 64, 607
LoongArch 64; ID 605 is absent from the extraction). Used to verify installs
from the booted media. Licence: **`GPL-3.0-or-later`** (Pete Batard's
project). Compatible. Uncertainty: the licence id is taken from the public
uefi-md5sum project, not from the binary itself; confirm when the payloads are
copied into `assets/` in S01 and during the S23 rebuild. Note ID 5 (`605`) is
absent in Rufus 4.15's resource tree — do not invent it.

### Microsoft KEK/DB certificates — RCDATA `701–704` (4 payloads)

What: four signed Microsoft UEFI KEK/DB certificate bundles (two date pairs,
2024-08-22 and 2025-05-15) consumed by the offline Secure Boot signature
analysis. Licence: these are **publicly distributed certificate data** —
Microsoft publishes exactly these X.509 blobs in its Secure Boot key
management material — redistributed here as *data*, not as licensed work.
SPDX for the manifest: `NOASSERTION` (data, no asserted licence; not a
Microsoft program). Uncertainty: bundle contents are content-based
inferences — **re-verify in S23** (which ports `hash`/`hash-efi` and
would own any certificate refresher).

## Compatibility conclusion

A `GPL-3.0-or-later` application (A1) may include **all** of the above:

* The Rufus-owned assets (icons, dialogs, VERSION, MANIFEST, glyphs 121–146,
  `rufus.loc`, `rufus.com`, uefi-ntfs.img, the setup wrapper 503/504) are the
  same licence as the rewrite itself — inclusion is trivially fine, with
  preserved attribution and the GPLv3 source offer.
* FreeDOS, Syslinux and GRUB4DOS payloads are `GPL-2.0-or-later`. "or-later"
  allows redistribution under GPL-3.0, and the rewrite is GPLv3-or-later, so
  combined distribution is licence-clean.
* **wimlib (`LGPL-3.0-or-later`, decision A5) is linked** through an FFI
  boundary, not statically absorbed into a proprietary product — and the
  product would not be proprietary in any case (GPLv3, A1). LGPL-3.0's
  relink/metadata requirements are satisfied by shipping the library as a
  separate package or noting the static-link source offer along with the
  GPLv3 source.
* `ntfs-3g`/`mkntfs` (`GPL-2.0-or-later`, A4) is executed as an external
  system tool, not embedded.
* Microsoft certificate bundles are public X.509 data used by the analysis;
  no incompatible licence attaches to certificate data redistribution.

**No asset with an incompatible licence was found in the 86 resources.** The
only non-code item is `NOASSERTION` certificate data (701–704), which is not a
licence conflict but an attribution/identification task for S23.

## Open items tracked from this audit

1. FreeDOS payload names (300–326): content-based inferences — re-verify in
   **S20**.
2. Certificate bundle exact contents (701–704): content-based inferences —
   re-verify in **S23**.
3. `RCDATA_452` authorship (GRUB4DOS message file vs. Rufus-authored
   screen): verify against upstream `pbatard/rufus` in **S19**; either answer
   keeps the compatibility conclusion.
4. uefi-md5sum licence id: confirm from the public project when copying
   assets in S01 and rebuilding in **S23**.
5. Trademark: the public name is not "Rufus" (decision A2; working name
   `rufus-linux`). Keep "Rufus" out of the distributed product identity.
