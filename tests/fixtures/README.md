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

Slice S05: the device-inspection fixtures are assembled in the test
process as well — MBR/GPT/BPB/LVM2 surfaces are byte buffers written into
sparse scratch files (`set_len` plus targeted writes), while mountinfo
and `/proc/swaps` are plain text files; nothing binary is committed. The
`analyze --device` integration tests pass `--device /dev/sdb` (or the
bare kernel name / sysfs path) plus the S05 `--device-file` hook aimed at
their sparse device buffer, so no real `/dev` node is needed.
