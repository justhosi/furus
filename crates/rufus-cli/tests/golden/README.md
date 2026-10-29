# Golden files (S03)

`plan-v1.json` is the exact `--json` output of

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

The test (`plan_dry_run_matches_golden_v1`, which lives in
`crates/rufus-cli/tests/cli.rs`) rebuilds
the same temp image from code (32,780 zero bytes with `CD001` at 0x8001 —
it must be ≥ 0x8006 bytes or the magic physically does not fit), runs the
binary with the same flags, applies the same normalisations, recomputes
`confirm` with `Plan::confirm()` and compares whole-JSON equality.

## Regeneration (after a deliberate `PLAN_VERSION` bump)

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
open("crates/rufus-cli/tests/golden/plan-v1.json", "w").write(
    json.dumps(plan, indent=2) + "\n")
EOF
```

`cargo xtask size --write-baseline` style discipline applies: regenerate by
hand when the schema changes, and the change must ship with a bumped
`PLAN_VERSION` (see `rufus-proto` docs on field order and confirm hashes).
