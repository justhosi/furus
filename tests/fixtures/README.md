# tests/fixtures/

Tiny binary fixtures for later slices (small ISOs, GPT/FAT images,
synthetic sysfs trees).

Slice S01: directory reserved, no fixtures yet. The QA harness that uses
them arrives in S27 (`xtask qa` is a stub until then).

Slice S04: device discovery needs no checked-in fixtures. Unit tests in
`crates/rufus-linux/src/sysfs.rs` and `watch.rs` build synthetic sysfs
trees in a `tempfile` directory at run time (`class/block/<name>/{size,
removable,dev,…}` plus an optional `run/udev/data`), and the CLI tests add
a trimmer tree through `--sysfs-root`. Keeping the trees in code means the
fixtures cannot rot and no binary blobs are committed.
