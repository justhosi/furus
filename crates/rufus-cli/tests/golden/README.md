# Golden files (S03)

`analyze-report.json` is the `report` object (only that object, not the
whole `analyze` output) for 4096 bytes of `0xAA` — the `RAW_SHA256`
constant in `crates/rufus-cli/tests/cli.rs`. Regenerate it with
`json.dumps(report, indent=2)` from `rufus analyze --json` over those
bytes.

`plan-v5.json` is the exact `--json` output of

```sh
rufus plan --dry-run --json --target bios --filesystem fat32 \
    --image fixture.iso --device /dev/null
```

after two normalisations that keep the file deterministic and
platform-independent:

* `image.path` → `"fixture.iso"` (the real invocation points at a temp file),
* `created_by` → `"<created_by>"` (it embeds the pkg version + git hash),
* `confirm` → recomputed over the *normalised* plan's canonical compact
  JSON (serde_json `to_vec` order = struct declaration order).

Schema v2 added `options.confirmed_serial` (the typed show-all
confirmation, PLAN §6 rule 4); schema v3 added the mkpart step's
`layout` (the partition layout the data window derives from); schema
v4 added the `kolibri` bootloader mode; schema v5 added the
`msdos` bootloader mode and `options.msdos_dir` (the user-supplied
MS-DOS directory, `null` here — an `msdos` plan would carry a path
and no write step, so the default `--bootloader auto` golden keeps
both the write step and the null). On this
golden `confirmed_serial` is `null` — the plan targets `/dev/null`
and never enables show-all — and `layout` is `"single"`, the
`--bootloader auto` default.

The test (`plan_dry_run_matches_golden_v5`, which lives in
`crates/rufus-cli/tests/cli.rs`) rebuilds
the same temp image from code (32,780 zero bytes with `CD001` at 0x8001 —
it must be ≥ 0x8006 bytes or the magic physically does not fit), runs the
binary with the same flags, applies the same normalisations, recomputes
`confirm` with `Plan::confirm()` and compares whole-JSON equality.

## Regeneration (after a reviewed plan-content change)

```sh
python3 - <<'EOF'
import hashlib, json

buf = bytearray(32_780)
buf[0x8001:0x8006] = b"CD001"

# Run the CLI once (image path points into a scratch dir):
#   rufus plan --dry-run --json --target bios --filesystem fat32 \
#      --image /tmp/fixture.iso --device /dev/null > raw.json
plan = json.load(open("raw.json"))
plan["image"]["path"] = "fixture.iso"
plan["created_by"] = "<created_by>"
plan["confirm"] = ""
plan["confirm"] = "sha256:" + hashlib.sha256(
    json.dumps(plan, separators=(",", ":")).encode()).hexdigest()
open("crates/rufus-cli/tests/golden/plan-v5.json", "w").write(
    json.dumps(plan, indent=2) + "\n")
EOF
```

`cargo xtask size --write-baseline` style discipline applies: regenerate by
hand when the plan schema changes **or** when a reviewed change to the
plan's content changes the output (as happened when the bootloader step
started pairing with the write mode, at the same schema version); a
schema change must ship with a bumped `PLAN_VERSION` (see `rufus-proto`
docs on field order and confirm hashes).
