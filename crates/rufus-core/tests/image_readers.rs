//! Real-image acceptance for the S15 container readers: 64 MiB
//! `qemu-img` 11.1.3 images (fixed and dynamic VHD, VHDX, qcow2) built
//! in an `archlinux:latest` container, read back through
//! [`rufus_core::image::open_image`](rufus_core::image::open_image)
//! byte-exactly against `qemu-img convert -O raw`, plus BAT/L2 mutant
//! proof restored byte-identically.
//!
//! What is measured here, image by image (each bullet names what this
//! run actually did; the container recipe is `pacman -Sy --noconfirm
//! qemu-img`, then the commands below over a 64 MiB raw file carrying
//! 32-byte markers at 0, 1 MiB, 2 MiB, 32 MiB and the last 512 bytes):
//! - fixed VHD (`qemu-img convert -f raw -O vpc -o subformat=fixed`):
//!   `open_image` reports `Vhd` with the footer's current size, and the
//!   logical stream hashes byte-exact to the `-f vpc -O raw`
//!   conversion; every marker reads back at its virtual offset.
//! - dynamic VHD (`-o subformat=dynamic`): `Vhd` with the same current
//!   size, 2 MiB blocks mapped through big-endian BAT sectors to a
//!   one-sector bitmap plus payload, byte-exact the same way.
//! - VHDX (`qemu-img convert -f raw -O vhdx`): `Vhdx` with the metadata
//!   virtual size, 8 MiB blocks through fully-present BAT entries,
//!   byte-exact the same way.
//! - qcow2 (`qemu-img convert -f raw -O qcow2`): `Qcow2` with the
//!   header virtual size, 64 KiB clusters through one L1 entry and
//!   copied L2 clusters, byte-exact the same way.
//! - mutants (on temp copies, each restored and re-hashed): a VHD BAT
//!   entry forced unallocated reads zeros where the marker was, and a
//!   sector past the file end refuses naming the entry; a VHDX BAT
//!   entry forced to state 2 reads zeros and to state 7 refuses; a
//!   qcow2 L2 entry with the compressed bit refuses and zeroed reads
//!   zeros.
//!
//! Both tests below are `#[ignore]`d: each one runs `docker run` and
//! installs `qemu-img` over the network inside the container, so
//! `cargo test --workspace` (what CI runs) must not depend on Arch
//! mirrors being reachable — under `--network none` the install
//! fails and the suite would go red instead of green. CI therefore
//! does not run this file; the mapping logic stays covered by the
//! synthetic `image::` unit tests, which need neither docker nor
//! network.
//!
//! Skip convention (the one tests/udf_format.rs carries): the suite
//! probes for `docker` first and prints an explicit `skip:` line when
//! it is missing - a skip is a documented limitation, never a silent
//! pass. The container needs network once (`pacman -Sy qemu-img`);
//! a container that spawns but misbehaves fails the test loudly
//! afterwards, which is the right bias.
//!
//! Run on demand on a host with docker plus network (the run takes on
//! the order of one to three minutes: one package install plus eight
//! 64 MiB conversions and the logical re-reads):
//!
//! ```text
//! cargo test --offline -p rufus-core --test image_readers -- --ignored --nocapture
//! ```
//!
//! FFU has no test here: no producer exists on this host (no DISM, no
//! Hyper-V), so its reader is synthetic-only and every claim about it
//! stays `Inferred` (see `image::ffu`).

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use rufus_core::image::ImageKind;
use rufus_core::image::open_image;
use sha2::Digest;
use sha2::Sha256;

/// The virtual size every fixture converts from: 64 MiB of raw.
const RAW_BYTES: u64 = 64 * 1024 * 1024;
/// Marker offsets inside the raw: the first byte, 1 MiB, 2 MiB,
/// 32 MiB and the last 512 bytes.
const MARKER_OFFSETS: [u64; 5] = [0, 1048576, 2097152, 33554432, 67108352];

/// Presence by spawn alone: a bare run with no arguments, spawn
/// success only, never an exit-code or output verdict (the
/// tests/udf_format.rs convention).
fn present(program: &str) -> bool {
    Command::new(program).output().is_ok()
}

/// The skip gate: without `docker` there are no fixtures to drive.
fn skip_without_docker(what: &str) -> bool {
    if present("docker") {
        return false;
    }
    eprintln!("skip: {what} needs docker, which this host does not ship");
    true
}

/// Run `script` in an `archlinux:latest` container with `dir` mounted
/// at `/work`: installs `qemu-img`, then fails the test with the real
/// output when anything misbehaves.
fn docker_sh(dir: &Path, script: &str) {
    let mount = format!("{}:/work", dir.display());
    let sh = format!("cd /work && pacman -Sy --noconfirm qemu-img >/dev/null 2>&1; {script}");
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &mount,
            "archlinux:latest",
            "sh",
            "-c",
            &sh,
        ])
        .output()
        .expect("docker spawns");
    assert!(
        output.status.success(),
        "docker qemu-img run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Fill `dir` with the fixtures: `base.raw` (64 MiB, markers at
/// [`MARKER_OFFSETS`]), the four conversions, and the four `-O raw`
/// references. Returns the base sha256 hex.
fn make_fixtures(dir: &Path) -> String {
    let mut dd = String::from("head -c 67108864 /dev/zero > base.raw; ");
    for (index, offset) in MARKER_OFFSETS.iter().enumerate() {
        dd.push_str(&format!(
            "printf 'RUFUS-S15-MARKER-{index:02}-AT-{offset:08}_' | \
             dd of=base.raw bs=1 seek={offset} conv=notrunc status=none; "
        ));
    }
    dd.push_str(
        "qemu-img convert -f raw -O vpc -o subformat=fixed base.raw fixed.vhd; \
         qemu-img convert -f raw -O vpc -o subformat=dynamic base.raw dyn.vhd; \
         qemu-img convert -f raw -O vhdx base.raw disk.vhdx; \
         qemu-img convert -f raw -O qcow2 base.raw disk.qcow2; \
         qemu-img convert -f vpc -O raw fixed.vhd ref-fixed.raw; \
         qemu-img convert -f vpc -O raw dyn.vhd ref-dyn.raw; \
         qemu-img convert -f vhdx -O raw disk.vhdx ref-vhdx.raw; \
         qemu-img convert -f qcow2 -O raw disk.qcow2 ref-qcow2.raw; \
         qemu-img info fixed.vhd; qemu-img info dyn.vhd; \
         qemu-img info disk.vhdx; qemu-img info disk.qcow2;",
    );
    docker_sh(dir, &dd);
    hex_of(&std::fs::read(dir.join("base.raw")).expect("base.raw converts"))
}

/// Lowercase hex sha256 of `bytes`.
fn hex_of(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Lowercase hex sha256 of the file at `path`.
fn hex_file(path: &Path) -> String {
    hex_of(&std::fs::read(path).expect("the fixture reads"))
}

/// The 32-byte marker written at `MARKER_OFFSETS[index]` (kept in
/// sync with the `printf` in [`make_fixtures`]: 17 + 2 + 4 + 8 + 1).
fn marker(index: usize, offset: u64) -> Vec<u8> {
    format!("RUFUS-S15-MARKER-{index:02}-AT-{offset:08}_").into_bytes()
}

/// Stream the whole logical image through 1 MiB reads: the sha256 hex
/// plus the marker bytes at each of [`MARKER_OFFSETS`].
fn read_logical(path: &Path) -> (String, Vec<Vec<u8>>) {
    let image = open_image(path).expect("the real image opens");
    let volume = image.into_volume();
    let total = volume.total_bytes();
    let mut hasher = Sha256::new();
    let mut rest = total;
    let mut offset = 0u64;
    let mut chunk = vec![0u8; 1024 * 1024];
    while rest > 0 {
        let want = (rest.min(chunk.len() as u64)) as usize;
        volume
            .read_exact_at(offset, &mut chunk[..want])
            .expect("the logical read fits");
        hasher.update(&chunk[..want]);
        offset += want as u64;
        rest -= want as u64;
    }
    let mut markers = Vec::new();
    for at in MARKER_OFFSETS.iter() {
        let mut found = vec![0u8; 32];
        if *at + 32 <= total {
            volume
                .read_exact_at(*at, &mut found)
                .expect("the marker read fits");
        }
        markers.push(found);
    }
    (format!("{:x}", hasher.finalize()), markers)
}

/// A big-endian `u64` at `at` of `bytes` (test-only parsing).
fn be_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(bytes[at..at + 8].try_into().expect("the field is 8 bytes"))
}

/// A little-endian `u64` at `at` of `bytes` (test-only parsing).
fn le_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("the field is 8 bytes"))
}

/// A little-endian `u32` at `at` of `bytes` (test-only parsing).
fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("the field is 4 bytes"))
}

/// Copy `path` to `path.with_extension("mut")` for mutant surgery.
fn mutant_copy(path: &Path) -> PathBuf {
    let copy = path.with_extension("mut");
    std::fs::copy(path, &copy).expect("the fixture copies");
    copy
}

#[test]
#[ignore = "needs docker and network (installs qemu-img); see the module docs"]
fn real_images_read_back_byte_exactly() {
    if skip_without_docker("the container-reader acceptance") {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let base_sha = make_fixtures(dir.path());
    assert_eq!(
        std::fs::metadata(dir.path().join("base.raw"))
            .expect("stat")
            .len(),
        RAW_BYTES
    );

    for (name, reference, kind) in [
        ("fixed.vhd", "ref-fixed.raw", ImageKind::Vhd),
        ("dyn.vhd", "ref-dyn.raw", ImageKind::Vhd),
        ("disk.vhdx", "ref-vhdx.raw", ImageKind::Vhdx),
        ("disk.qcow2", "ref-qcow2.raw", ImageKind::Qcow2),
    ] {
        let path = dir.path().join(name);
        let image = open_image(&path).expect("the real image opens");
        assert_eq!(image.kind(), kind, "{name}");
        let reference_bytes = std::fs::read(dir.path().join(reference)).expect("reference reads");
        assert_eq!(
            image.size_bytes(),
            reference_bytes.len() as u64,
            "{name}: virtual size is the conversion length"
        );
        let (sha, markers) = read_logical(&path);
        assert_eq!(
            sha,
            hex_of(&reference_bytes),
            "{name}: logical bytes are the conversion"
        );
        if sha == base_sha {
            // The conversion is the stamped raw itself (dynamic VHD,
            // VHDX, qcow2 at exactly 64 MiB).
        } else {
            // Fixed VHD rounds the virtual size up past the raw (CHS
            // geometry): the head must be the raw, the tail zeros.
            assert_eq!(
                &reference_bytes[..RAW_BYTES as usize],
                &std::fs::read(dir.path().join("base.raw")).expect("base reads")[..],
                "{name}: head is the raw"
            );
            let tail = &reference_bytes[RAW_BYTES as usize..];
            assert!(!tail.is_empty(), "{name}: virtual size exceeds the raw");
            assert!(
                tail.iter().all(|byte| *byte == 0),
                "{name}: tail past raw is zeros"
            );
        }
        for (index, offset) in MARKER_OFFSETS.iter().enumerate() {
            if *offset + 32 <= reference_bytes.len() as u64 {
                assert_eq!(
                    markers[index],
                    marker(index, *offset),
                    "{name}: marker at {offset}"
                );
            }
        }
    }
}

#[test]
#[ignore = "needs docker and network (installs qemu-img); see the module docs"]
fn table_mutants_restore_byte_identically() {
    if skip_without_docker("the table-mutant proof") {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    make_fixtures(dir.path());

    // VHD BAT: the footer (last 512 bytes) points at the dynamic
    // header, whose table offset starts the BAT (big-endian sectors).
    {
        let path = dir.path().join("dyn.vhd");
        let pristine = hex_file(&path);
        let copy = mutant_copy(&path);
        let mut bytes = std::fs::read(&copy).expect("the copy reads");
        let total = bytes.len();
        let data_offset = be_u64(&bytes, total - 512 + 16) as usize;
        let table_offset = be_u64(&bytes, data_offset + 16) as usize;
        let before = bytes[table_offset..table_offset + 4].to_vec();

        // Forced unallocated: block 0 (the marker block) reads zeros.
        bytes[table_offset..table_offset + 4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        std::fs::write(&copy, &bytes).expect("the mutant writes");
        let image = open_image(&copy).expect("the mutant opens");
        let mut block = vec![0u8; 512];
        image
            .volume()
            .read_exact_at(0, &mut block)
            .expect("the zeroed block reads");
        assert_eq!(block, vec![0u8; 512]);

        // A sector past the file end refuses naming the entry.
        bytes[table_offset..table_offset + 4].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes());
        std::fs::write(&copy, &bytes).expect("the mutant writes");
        let image = open_image(&copy).expect("the mutant opens");
        let error = image.volume().read_exact_at(0, &mut block).unwrap_err();
        assert!(error.to_string().contains("BAT entry 0"), "{error:?}");

        bytes[table_offset..table_offset + 4].copy_from_slice(&before);
        std::fs::write(&copy, &bytes).expect("the restore writes");
        assert_eq!(
            hex_file(&copy),
            pristine,
            "the VHD mutant restored byte-identically"
        );
        eprintln!("vhd mutant restored byte-identically: sha256 {pristine}");
    }

    // VHDX BAT states: the region table at 192 KiB names the BAT
    // offset; entry 0 is rewritten to state 2 (zero) and state 7
    // (partially present, refused).
    {
        let path = dir.path().join("disk.vhdx");
        let pristine = hex_file(&path);
        let copy = mutant_copy(&path);
        let mut bytes = std::fs::read(&copy).expect("the copy reads");
        let region = 192 * 1024;
        let count = le_u32(&bytes, region + 8) as usize;
        let bat_guid: [u8; 16] = [
            0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD,
            0x4A, 0x08,
        ];
        let mut bat_offset = 0usize;
        for index in 0..count {
            let at = region + 16 + index * 32;
            if bytes[at..at + 16] == bat_guid {
                bat_offset = le_u64(&bytes, at + 16) as usize;
            }
        }
        assert!(bat_offset != 0, "the BAT region is found");
        let before = bytes[bat_offset..bat_offset + 8].to_vec();

        bytes[bat_offset..bat_offset + 8].copy_from_slice(&2u64.to_le_bytes());
        std::fs::write(&copy, &bytes).expect("the mutant writes");
        let image = open_image(&copy).expect("the mutant opens");
        let mut block = vec![0u8; 512];
        image
            .volume()
            .read_exact_at(0, &mut block)
            .expect("the zeroed block reads");
        assert_eq!(block, vec![0u8; 512]);

        let entry = le_u64(&before, 0);
        bytes[bat_offset..bat_offset + 8].copy_from_slice(&((entry & !7) | 7).to_le_bytes());
        std::fs::write(&copy, &bytes).expect("the mutant writes");
        let image = open_image(&copy).expect("the mutant opens");
        let error = image.volume().read_exact_at(0, &mut block).unwrap_err();
        assert!(
            error.to_string().contains("only fully present"),
            "{error:?}"
        );

        bytes[bat_offset..bat_offset + 8].copy_from_slice(&before);
        std::fs::write(&copy, &bytes).expect("the restore writes");
        assert_eq!(
            hex_file(&copy),
            pristine,
            "the VHDX mutant restored byte-identically"
        );
        eprintln!("vhdx mutant restored byte-identically: sha256 {pristine}");
    }

    // qcow2 L2: the header names the L1 table, whose first entry
    // names the L2 table; L2[0] gains the compressed bit (refused)
    // and then loses its cluster (zeros).
    {
        let path = dir.path().join("disk.qcow2");
        let pristine = hex_file(&path);
        let copy = mutant_copy(&path);
        let mut bytes = std::fs::read(&copy).expect("the copy reads");
        let l1_offset = be_u64(&bytes, 40) as usize;
        let l1_entry = be_u64(&bytes, l1_offset);
        let l2_base = (l1_entry & 0x00_FFFF_FFFF_FE00) as usize;
        assert!(l2_base != 0, "the L2 table is found");
        let before = bytes[l2_base..l2_base + 8].to_vec();

        let entry = u64::from_be_bytes(before.as_slice().try_into().expect("8 bytes"));
        bytes[l2_base..l2_base + 8].copy_from_slice(&(entry | (1 << 62)).to_be_bytes());
        std::fs::write(&copy, &bytes).expect("the mutant writes");
        let image = open_image(&copy).expect("the mutant opens");
        let mut cluster = vec![0u8; 512];
        let error = image.volume().read_exact_at(0, &mut cluster).unwrap_err();
        assert!(error.to_string().contains("compressed"), "{error:?}");

        bytes[l2_base..l2_base + 8].copy_from_slice(&0u64.to_be_bytes());
        std::fs::write(&copy, &bytes).expect("the mutant writes");
        let image = open_image(&copy).expect("the mutant opens");
        image
            .volume()
            .read_exact_at(0, &mut cluster)
            .expect("the zeroed cluster reads");
        assert_eq!(cluster, vec![0u8; 512]);

        bytes[l2_base..l2_base + 8].copy_from_slice(&before);
        std::fs::write(&copy, &bytes).expect("the restore writes");
        assert_eq!(
            hex_file(&copy),
            pristine,
            "the qcow2 mutant restored byte-identically"
        );
        eprintln!("qcow2 mutant restored byte-identically: sha256 {pristine}");
    }
}
