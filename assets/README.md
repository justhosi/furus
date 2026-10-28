# assets/

Binary payloads reused from Rufus 4.15.2396 (GPLv3 family; see `LICENSES.md`).

* `manifest.json` — frozen S00 deliverable: 86 entries with `id`, `name`,
  `bytes`, `sha256`, `source` and `licence`. Do not edit.
* `resources/` — copied verbatim from `example/resources` (extracted from
  `rufus-4.15.exe`): 86 files, sizes and hashes pinned by `manifest.json`.
  Not regenerated here; `cargo xtask assets --check` verifies every file.
