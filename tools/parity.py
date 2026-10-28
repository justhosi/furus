#!/usr/bin/env python3
"""Generate the function-parity ledger for the Rust rewrite.

Input : ../example/functions.csv  (2,674 internal functions + 35 thunks)
Output: parity.csv

Every analysed function gets exactly one disposition:
  port         first-party logic re-implemented in Rust (slice assigned)
  c-ffi       replaced by linking an existing C library
  system-tool replaced by calling an external, vetted Linux tool
  crate       replaced by a Rust crate
  replace     replaced by Rust std / libc / OS facility
  thunk       PLT/thunk row, follows its module

Run from anywhere:  python3 tools/parity.py
"""

from __future__ import annotations

import csv
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE.parent / "data" / "functions.csv"
DST = HERE.parent / "data" / "parity.csv"

# module -> (disposition, slice, note)
BY_MODULE: dict[str, tuple[str, str, str]] = {
    "badblocks":       ("port",        "S17", "bad-block scan + report"),
    "cregex":          ("port",        "S03", "console argument parser"),
    "dos_locale":      ("port",        "S20", "FreeDOS codepage/keyboard tables"),
    "drive":           ("port",        "S05", "disk/volume introspection"),
    "registry":        ("replace",     "S02", "TOML config; policy under /etc"),
    "stdfn":           ("port",        "S02", "string/path helpers"),
    "stdio":           ("port",        "S02", "logging + buffered I/O"),
    "process":         ("port",        "S06", "std::process + pipe capture"),
    "rufus":           ("port",        "S16", "image classification/dispatch"),
    "syslinux":        ("port",        "S19", "Syslinux install/patch"),
    "stdlg":           ("port",        "S24", "Slint dialogs / window logic"),
    "hash-efi":        ("port",        "S23", "SBAT + EFI boot-file fixup"),
    "hash":            ("port",        "S23", "MD5/SHA1/SHA256/SHA512"),
    "ui":              ("port",        "S24", "Slint widgets / status drawing"),
    "iso":             ("port",        "S18", "ISO tree extraction/copy"),
    "net":             ("port",        "S25", "HTTP update check / download"),
    "vhd":             ("port",        "S15", "VHD/FFU container handling"),
    "wue":             ("port",        "S22", "Windows User Experience"),
    "format":          ("port",        "S17", "format pipeline (sub-slices below)"),
    "format_ext":      ("port",        "S12", "ext2/3/4 creation"),
    "ui/ffu":          ("port",        "S21", "FFU/WIM helpers"),
    "dev":             ("port",        "S04", "USB device discovery/filtering"),
    "format_fat32":    ("port",        "S09", "large FAT32 formatter"),
    "icon":            ("port",        "S24", "icon loader"),
    "getopt":          ("crate",       "S03", "clap"),
    "expat-xml":       ("crate",       "S16", "quick-xml"),
    "libcdio-iso9660": ("port",        "S14", "ISO9660/Joliet/Rock Ridge reader"),
    "syslinux-libinstaller": ("port",  "S19", "FAT + syslinux_patch port"),
    "ext2fs":          ("system-tool", "S12", "mke2fs (optional libext2fs feature)"),
    "wimlib":          ("c-ffi",       "S21", "wimlib (LGPLv3+) via FFI"),
    "compression":     ("crate",       "S17", "zstd/xz2/bzip2/flate2"),
    "crt":             ("replace",     "",    "Rust std / libc"),
    "other":           ("port",        "S02", "misc helper"),
}

# Address-specific corrections where the module attribution is too coarse.
OVERRIDES: dict[str, tuple[str, str, str]] = {
    "0x14000b800": ("port", "S05", "volume/drive property helper"),
    "0x14000bc60": ("port", "S05", "drive geometry/layout log"),
    "0x14000c720": ("port", "S06", "mount volume via helper"),
    "0x14000c920": ("port", "S06", "pick unused mount point"),
    "0x14000ca00": ("port", "S06", "unmount volume"),
    "0x14000ca80": ("port", "S06", "flush + remount volume"),
    "0x14000cc20": ("port", "S20", "write UEFI:NTFS image + partition"),
    "0x14000dbd0": ("port", "S05", "exclude disk by GUID"),
    "0x14000df00": ("port", "S08", "delete partition helper"),
    "0x14000df80": ("port", "S08", "partition table helper"),
    "0x14000dfe0": ("port", "S02", "settings key helper"),
    "0x14000e200": ("port", "S08", "wipe MBR/GPT areas"),
    "0x14000e230": ("port", "S08", "wipe helper"),
    "0x14000e310": ("port", "S12", "filesystem format dispatcher"),
    "0x14000e700": ("port", "S23", "filesystem check callback"),
    "0x14000e860": ("port", "S09", "FAT label fallback"),
    "0x14000eb70": ("port", "S12", "format via VDS (replaced)"),
    "0x14000f470": ("port", "S12", "format via IFS (replaced)"),
    "0x14000f7c0": ("port", "S12", "format helper"),
    "0x14000f8c0": ("port", "S08", "reset disk + initialise layout"),
    "0x14000fa40": ("port", "S09", "FAT type + boot flag"),
    "0x14000fef0": ("port", "S19", "GRUB4DOS / GRUB2 SBR"),
    "0x140010320": ("port", "S20", "partition boot record selection"),
    "0x1400107c0": ("port", "S17", "write helper"),
    "0x140010830": ("port", "S17", "write helper"),
    "0x140010a40": ("port", "S17", "image writer"),
    "0x140011ac0": ("port", "S17", "pipeline orchestrator"),
    "0x140014650": ("port", "S20", "MS-DOS FAT extraction"),
    "0x140014bd0": ("port", "S20", "MS-DOS boot files"),
    "0x1400150c0": ("port", "S20", "FreeDOS boot files"),
    "0x140015b50": ("port", "S12", "ext2/3/4 formatter"),
    "0x140016ad0": ("port", "S09", "large FAT32 formatter"),
    "0x140017a90": ("port", "S14", "ISO temp file helper"),
    "0x140017c30": ("port", "S14", "ISO helper"),
    "0x140017cc0": ("port", "S14", "ISO helper"),
    "0x140017f40": ("port", "S14", "ISO string array"),
    "0x1400190e0": ("port", "S18", "persistence config"),
    "0x140019ad0": ("port", "S18", "path sanitisation"),
    "0x14001a670": ("port", "S18", "ISO copy"),
    "0x140061020": ("port", "S21", "apply WIM image"),
    "0x140061dd0": ("port", "S21", "capture/apply FFU"),
}


def main() -> int:
    if not SRC.exists():
        print(f"missing {SRC}", file=sys.stderr)
        return 1
    rows = list(csv.DictReader(SRC.open(newline="", encoding="utf-8")))
    out = []
    for row in rows:
        addr = row["address"]
        module = row["module"]
        kind = row["kind"]
        if addr in OVERRIDES:
            disp, slice_id, note = OVERRIDES[addr]
        elif module in BY_MODULE:
            disp, slice_id, note = BY_MODULE[module]
        else:
            disp, slice_id, note = ("port", "S02", "unclassified module")
        if kind == "thunk":
            disp = "thunk"
            note = f"thunk -> {note}"
        out.append(
            {
                "address": addr,
                "name": row["name"],
                "size": row["size"],
                "module": module,
                "kind": kind,
                "disposition": disp,
                "slice": slice_id,
                "notes": note,
            }
        )

    DST.parent.mkdir(parents=True, exist_ok=True)
    with DST.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(out[0].keys()))
        writer.writeheader()
        writer.writerows(out)

    from collections import Counter

    by_disp = Counter(r["disposition"] for r in out)
    by_slice = Counter(r["slice"] for r in out if r["slice"])
    print(f"wrote {DST} ({len(out)} rows)")
    for name, count in sorted(by_disp.items()):
        print(f"  {name:<12} {count}")
    print("  per slice:")
    for name, count in sorted(by_slice.items()):
        print(f"    {name:<5} {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
