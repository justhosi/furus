# Handoff — S23 Slice 1/1 (planner extraction, bootloader split, bad-blocks docs)

## Status
Complete, reviewed and published. Five commits on top of `3545058` (S22 docs tip),
pushed to `origin/main` at `f12be17` by the publisher (S23 publish permission was
given explicitly). Working tree clean after the review commits.

## Scope
Slice instruction: `s23_shared_planner_and_bootloader_modularization.md` (S23-T1/T2/T3).
No behaviour change was in scope: no CLI flag, no `PLAN_VERSION` 6 plan shape, no
on-disk bootloader behaviour, no exit-code change.

## Commit map
| Commit | Subject |
|---|---|
| `06b8e26` | `refactor: extract the shared plan builder into furus-core` (S23-T1) |
| `254f866` | `refactor: split the bootloader pipeline into arm submodules` (S23-T2) |
| `ef2cbfa` | `docs: reconcile bad-blocks with the full-format path` (S23-T3) |
| `c7832cd` | `fix: restore the bootloader module tree and drop the empty test module` (review fix, on top of `ef2cbfa`) |
| `f12be17` | `docs: record S23 and correct the stale bootloader paths` (review docs) |

## What was done

### T1 — shared planner (`crates/furus-core/src/planner/mod.rs`, 1,186 lines)
`furus-cli`'s plan builder (`plan.rs`, 1,162 lines) and its image preamble moved
into `furus-core` so the S24 Slint GUI can build the same `Plan`:

* `BootloaderOpt` (`mode()`, `layout()`), `Options`, `write_mode()`, `steps()`,
  `build()` — logic and refusal strings are the pre-extraction ones, verified
  token-for-token against `git show 3545058:crates/furus-cli/src/plan.rs`.
* `DeviceProbe`/`DeviceFacts` replace the direct `furus_linux::enumerate` call:
  `furus-core` only grades the facts, `furus-linux` fills them
  (`probe_device(path, sysfs)`, `plan_device_ref(&Device)`). `furus-core` still
  does not depend on `furus-linux`.
* `PlanError { Device, Safety, Usage, Confirm }` replaces `furus_cli::Fail`
  inside the builder; `main.rs::fail_from_plan` maps it to exit 2/3/1/4 with the
  same `device`/`safety`/`usage`/`json` kinds.
* Image inspection moved to `furus_core::image::{inspect, file_size,
  detect_file}` → `ImageInfo`; `crates/furus-cli/src/image.rs` is a 9-line
  re-export surface keeping the `image_size` spelling.
* `crates/furus-cli/src/plan.rs` is 85 lines: the `clap::ValueEnum` twin plus
  `From<BootloaderOpt> for CoreBootloaderOpt` and one test that walks all ten
  variants.

### T2 — bootloader submodules (`pipeline/bootloader/`, 7,706 lines total)
`mod.rs` (dispatch, `Installed`, `DiskView`/`gap_end`, post-MBR-gap bound),
`syslinux.rs`, `grub2.rs`, `grub4dos.rs`, `dos_kolibri.rs` (FreeDOS, KolibriOS,
MS-DOS), `uefi_ntfs.rs`, `windows.rs`; tests under `tests/` (52) and
`end_to_end/` (9, including the QEMU VGA harness in `qemu.rs` and the 4 QEMU boot
tests in `qemu_boot.rs`). Public surface unchanged (`Installed`, `install_tree`,
`run` stay `pub(crate)`; arms `pub(super)`); every file ≤1,646 lines.

### T3 — bad-blocks documentation
`mkfs.rs` no longer claims the scan "arrives in slice 9": full format only zeroes,
the scan is the wipe's opt-in `"badblocks"` pseudo-step (`RunOptions::badblocks`)
that finishes before table/partition/format. Pinned by
`full_format_zeroes_without_scanning_and_scan_rides_in_wipe`.

## Round-1 review findings and their fixes (uncommitted work the reviewer closed)
1. `end_to_end/qemu.rs` was committed with the old inline-module shell: it still
   declared `mod qemu; mod qemu_boot;` inside itself (E0583 — `qemu.rs` resolving
   its own name), kept the 4-space body indent and one extra `}` (31 `{` vs 32
   `}`), and had lost the last line of its doc block. Fixed: `end_to_end/mod.rs`
   now declares `mod qemu; mod qemu_boot;`, and `qemu.rs`/`qemu_boot.rs` are
   top-level modules; their token streams are now identical to the pre-split
   file (checked whitespace-insensitively).
2. `tests/support.rs` (a 7-line doc-only placeholder) and its `mod support;`
   declaration were dead weight from the split. Deleted.
3. `planner/mod.rs` linked `[`Device`]`, which does not exist in that module
   (rustdoc broken link). Now plain backticks.

## Verification (reviewer, at the committed tip)
* `cargo fmt --all --check` — clean.
* `cargo clippy --workspace --all-targets -- -D warnings` — clean.
* `cargo test --workspace` — 1,747 passed / 0 failed / 29 ignored; `furus-core`
  lib 1,316 passed / 6 ignored. `cargo test -p furus-core --lib -- --list`
  shows 61 `pipeline::bootloader` tests (52 unit + 5 `end_to_end` + 4
  `end_to_end::qemu_boot`); the 4 QEMU tests run — 3 pass
  (`syslinux_407_…`, `freedos_…`, `grub2_bios_…`) and
  `grub4dos_boots_to_its_prompt_in_qemu` stays `#[ignore]`d behind
  `FURUS_TEST_GRLDR` exactly as before the split.
* `cargo xtask parity --check` — 2,709 rows, S23 = 42, data fresh.
* `cargo xtask ci` — `ci: all gates passed`; assets 86/86; size furus
  1,810,200 / helper 1,385,080 / gui 284,008, all within budget, matching the
  refreshed baseline; `cargo-deny`/`cargo-audit` SKIPped (not installed).
* All of the above were run with
  `export PATH="$HOME/.cargo/bin:$PATH"` and
  `export FURUS_ASSETS="$PWD/assets/resources"`. The variable is a *runtime*
  asset override (`furus_core::paths`); the test suites resolve fixtures through
  `CARGO_MANIFEST_DIR/../../assets/resources` and do not need it, so a bare
  `cargo test` works too.
* `cargo doc -p furus-core --no-deps` — 225 pre-existing warnings; the only new
  one is `pipeline/mkfs.rs:23` (`[`Wipe`](super::wipe::run)` links to a private
  item), the same warning class `badblocks.rs:19` has carried since S09. Doc
  warnings are not gated.

## Gotchas for the next session
* The QEMU boot tests need `qemu-system-x86_64` on `PATH` and *silently skip*
  (one `skip:` line) without it, so a green run on a machine without QEMU proves
  nothing about booting. They boot a 128 MiB full-plan disk image (partition
  table included) and read the VGA text buffer through the monitor socket.
* `tests/support.rs` was never a real module; if a fixture needs to exist for
  more than one arm, put it in `bootloader/tests/mod.rs` (that is where the
  shared fixtures already live) — do not reintroduce an empty file.
* The four QEMU tests now sit under `end_to_end::qemu_boot::*`. If you filter
  them by name, use that path; nothing else references them.
* `254f866` and `ef2cbfa` do not build on their own (the split shipped the
  broken `qemu.rs` shell above); the review fix commit restores the tree. `git
  bisect` across those two revisions will land on non-building commits until the
  S23 commits are squashed or the history is rewritten with the user's consent.
* The three coder commits carry no `Reviewed-by: reviewer` trailer (the review
  commit does). Every other commit in this repository has it, so the trailer is
  missing on `06b8e26`, `254f866` and `ef2cbfa` until an amend/rebase the review
  phase must not perform.

## Next steps
1. Published: `main` pushed to `origin` at `f12be17` by the publisher under the
   user's explicit S23 publish permission.
2. S24 (Slint GUI) can now call `furus_core::planner` directly:
   `Options` + `BootloaderOpt` from the form, `furus_linux::plan_device_ref` for
   a selected `Device` (or `probe_device` for a typed path), and
   `furus_core::image::inspect` for the image — no rule has to be duplicated.
3. Open follow-ups, all non-blocking: give `qemu.rs` a real `//!` module doc
   (its header is still a `///` block attached to the first `use`); make
   `mkfs.rs:23`'s `Wipe` link point at a public item (or use plain backticks);
   consider dropping `planner::DeviceProbe::unknown` (public, test-only today).
