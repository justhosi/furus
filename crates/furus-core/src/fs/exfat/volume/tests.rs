use super::io::slot_image;
use super::*;
use crate::fs::VecVolume;
use crate::fs::exfat::format;
use std::cell::Cell;
use std::rc::Rc;

const MIB: u64 = 1024 * 1024;
const SERIAL: u32 = 0x5EED_1234;

fn formatted() -> Exfat<VecVolume> {
    let volume = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
    let options = format::FormatOptions::new(SERIAL);
    Exfat::format(volume, &options).expect("the formatter accepts this store")
}

/// A formatted volume whose store can be told to fail on the Nth
/// write: the seam the torn-write and rollback tests drive.
fn flaky_formatted() -> Exfat<Flaky> {
    let volume = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
    let options = format::FormatOptions::new(SERIAL);
    Exfat::format(Flaky::new(volume), &options).expect("the formatter accepts this store")
}

fn names(listing: &[DirInfo]) -> Vec<&str> {
    listing.iter().map(|entry| entry.name.as_str()).collect()
}

/// The stream entry of the file at `path`, read out of its
/// parent's live directory content: `(first cluster, data length,
/// valid data length)` — the three on-disk facts `write_at` owns
/// and the tests pin.
#[track_caller]
fn stream_entry(volume: &Exfat<VecVolume>, path: &str) -> (u32, u64, u64) {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let leaf = parts.last().copied().expect("the path has a leaf");
    let parents: Vec<String> = parts
        .iter()
        .take(parts.len().saturating_sub(1))
        .map(|part| (*part).to_owned())
        .collect();
    let levels = volume.walk(&parents).expect("the parent directory walks");
    let parent = levels.last().expect("the parent is in the walk");
    let listing = dirent::parse_dir_listing(&parent.content.bytes).expect("the listing parses");
    let cluster_bytes = usize::try_from(volume.geometry().cluster_bytes())
        .expect("a cluster fits this machine's usize");
    for (entry, start) in listing.entries.iter().zip(listing.set_starts.iter()) {
        if dirent::upcase_name(&entry.name) != dirent::upcase_name(leaf) {
            continue;
        }
        let image =
            slot_image(&parent.content, cluster_bytes, start + 1).expect("the stream slot reads");
        return (
            get_u32(&image, 20).unwrap_or(0),
            get_u64(&image, 24).unwrap_or(0),
            get_u64(&image, 8).unwrap_or(0),
        );
    }
    panic!("the file {path} is not in its parent's listing");
}

/// Overwrite the `ValidDataLength` of the file at `path` directly
/// on the image (set checksum recomputed) — the corruption-shaped
/// entry the refusal tests drive against, which the volume API
/// would never write itself.
#[track_caller]
fn patch_valid_length(volume: &mut Exfat<VecVolume>, path: &str, valid: u64) {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let leaf = parts.last().copied().expect("the path has a leaf");
    let parents: Vec<String> = parts
        .iter()
        .take(parts.len().saturating_sub(1))
        .map(|part| (*part).to_owned())
        .collect();
    let levels = volume.walk(&parents).expect("the parent directory walks");
    let parent = levels.last().expect("the parent is in the walk");
    let listing = dirent::parse_dir_listing(&parent.content.bytes).expect("the listing parses");
    let cluster_bytes = usize::try_from(volume.geometry().cluster_bytes())
        .expect("a cluster fits this machine's usize");
    let mut start = None;
    for (entry, found) in listing.entries.iter().zip(listing.set_starts.iter()) {
        if dirent::upcase_name(&entry.name) == dirent::upcase_name(leaf) {
            start = Some(*found);
        }
    }
    let start = start.expect("the file is in the listing");
    let set_end = listing
        .set_starts
        .iter()
        .copied()
        .find(|found| *found > start)
        .unwrap_or(listing.terminator_slot);
    let mut images: Vec<[u8; 32]> = (start..set_end)
        .map(|slot| slot_image(&parent.content, cluster_bytes, slot).expect("the slot reads"))
        .collect();
    put_u64(
        images.get_mut(1).expect("the set has a stream slot"),
        8,
        valid,
    )
    .expect("the valid field fits");
    let checksum = dirent::set_checksum(&images);
    let mut lead = images.first().copied().expect("the set has a lead");
    put_u16(&mut lead, 2, checksum).expect("the checksum field fits");
    let stream_image = images.get(1).copied().expect("the set has a stream slot");
    let file_at = parent
        .content
        .slot_address(volume.geometry(), start)
        .expect("the file slot has an address");
    let stream_at = parent
        .content
        .slot_address(volume.geometry(), start + 1)
        .expect("the stream slot has an address");
    volume
        .volume
        .write_all_at(file_at, &lead)
        .expect("the patched file slot writes");
    volume
        .volume
        .write_all_at(stream_at, &stream_image)
        .expect("the patched stream slot writes");
}

#[test]
fn a_created_tree_lists_back_in_creation_order() {
    let mut volume = formatted();

    volume
        .mkdir("/docs", dirent::Stamps::epoch())
        .expect("the directory is created");
    volume
        .create_file("/docs/readme.txt", 0, dirent::Stamps::epoch())
        .expect("the empty file is created");
    volume
        .create_file("/docs/Mixed Case.txt", 0, dirent::Stamps::epoch())
        .expect("the mixed-case file is created");

    let root = volume.list_dir("/").expect("the root lists");
    assert_eq!(names(&root), ["docs"]);
    assert!(root[0].is_dir, "the root entry is a directory");
    assert_eq!(
        root[0].size,
        volume.geometry().cluster_bytes(),
        "a directory reports its whole allocation"
    );

    let docs = volume.list_dir("/docs").expect("the directory lists");
    assert_eq!(names(&docs), ["readme.txt", "Mixed Case.txt"]);
    assert!(!docs[0].is_dir, "a file is not a directory");
    assert_eq!(docs[1].size, 0, "an empty file allocates nothing");
}

#[test]
fn a_fresh_volume_lists_nothing_and_hides_the_system_entries() {
    let volume = formatted();
    assert!(
        volume.list_dir("/").expect("the root lists").is_empty(),
        "the bitmap, up-case and label entries never list"
    );
}

#[test]
fn a_duplicate_name_is_refused_case_insensitively() {
    let mut volume = formatted();
    volume
        .create_file("/notes.txt", 0, dirent::Stamps::epoch())
        .expect("the first file is created");

    let error = volume
        .create_file("/NOTES.TXT", 0, dirent::Stamps::epoch())
        .expect_err("the second name collides");
    let message = error.to_string();
    assert!(
        message.contains("exists"),
        "the refusal names the collision: {message}"
    );
    assert_eq!(
        names(&volume.list_dir("/").expect("the root lists")),
        ["notes.txt"],
        "the refused create added nothing"
    );
}

#[test]
fn a_create_with_no_room_rolls_the_ledger_back() {
    let mut volume = formatted();
    let free_before = volume.free_bytes();
    let clusters_before = volume.bitmap.free_clusters();

    let error = volume
        .create_file("/huge.bin", 64 * MIB, dirent::Stamps::epoch())
        .expect_err("the volume cannot hold this file");
    assert!(
        error.to_string().contains("cluster"),
        "the refusal reports the allocation: {error}"
    );
    assert_eq!(volume.free_bytes(), free_before, "the ledger is restored");
    assert_eq!(volume.bitmap.free_clusters(), clusters_before);
    assert!(
        volume.list_dir("/").expect("the root lists").is_empty(),
        "the refused create left no entry"
    );
}

#[test]
fn directories_grow_past_one_cluster_in_the_root_and_in_a_subdirectory() {
    let mut volume = formatted();
    let slots_per_cluster = usize::try_from(volume.geometry().cluster_bytes() / 32)
        .expect("a cluster holds a whole number of slots");
    // Every short-named file is a three-slot set, so this many
    // entries cannot fit one cluster.
    let count = slots_per_cluster / 3 + 4;

    volume
        .mkdir("/inner", dirent::Stamps::epoch())
        .expect("the directory is created");
    for index in 0..count {
        volume
            .create_file(&format!("/f{index:04}.bin"), 0, dirent::Stamps::epoch())
            .expect("the root accepts the entry");
        volume
            .create_file(
                &format!("/inner/g{index:04}.bin"),
                0,
                dirent::Stamps::epoch(),
            )
            .expect("the subdirectory accepts the entry");
    }

    assert_eq!(
        volume.list_dir("/").expect("the root lists").len(),
        count + 1
    );
    assert_eq!(
        volume
            .list_dir("/inner")
            .expect("the directory lists")
            .len(),
        count
    );
    for index in 0..count {
        let name = format!("f{index:04}.bin");
        assert!(
            volume
                .list_dir("/")
                .expect("the root lists")
                .iter()
                .any(|entry| entry.name == name),
            "the entry {name} survives the growth"
        );
    }
}

#[test]
fn flush_publishes_the_allocated_percentage_of_the_used_clusters() {
    let mut volume = formatted();
    // Three mebibytes of an eight mebibyte volume: a floored
    // percentage that is far from zero, so "always write 0" fails.
    volume
        .create_file("/payload.bin", 3 * MIB, dirent::Stamps::epoch())
        .expect("the file is created");

    let cluster_count = u64::from(volume.geometry().cluster_count);
    let used = cluster_count - u64::from(volume.bitmap.free_clusters());
    let expected = u8::try_from(used * 100 / cluster_count).expect("a percentage fits a byte");
    assert!(
        expected >= 30,
        "the fixture must keep the percentage away from zero"
    );

    volume.flush().expect("the volume flushes");
    let boot = volume
        .volume
        .bytes()
        .get(..512)
        .expect("the boot sector exists");
    assert_eq!(
        boot[PERCENT_IN_USE_AT], expected,
        "byte 112 carries the floored percentage of allocated clusters"
    );
    // The backup boot region carries the same byte.
    let backup = volume
        .volume
        .bytes()
        .get(12 * 512..13 * 512)
        .expect("the backup boot sector exists");
    assert_eq!(backup[PERCENT_IN_USE_AT], expected);
}

/// A store that can be told to fail the next write, so a create
/// path that fails *after* its first allocation is reachable.
struct Flaky {
    inner: VecVolume,
    fail_after: Rc<Cell<Option<u64>>>,
    writes: Rc<Cell<u64>>,
}

impl Flaky {
    fn new(store: VecVolume) -> Self {
        Self {
            inner: store,
            fail_after: Rc::new(Cell::new(None)),
            writes: Rc::new(Cell::new(0)),
        }
    }
}

impl Volume for Flaky {
    fn total_bytes(&self) -> u64 {
        self.inner.total_bytes()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read_exact_at(offset, buf)
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if let Some(limit) = self.fail_after.get() {
            if self.writes.get() >= limit {
                // One shot: the rollback that follows a real I/O
                // error must be able to write, so the injected
                // failure happens exactly once.
                self.fail_after.set(None);
                return Err(CoreError::io(
                    "<flaky store>",
                    std::io::Error::other("injected write failure"),
                ));
            }
            self.writes.set(self.writes.get() + 1);
        }
        self.inner.write_all_at(offset, buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }

    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }
}

#[test]
fn a_subdirectory_grows_in_place_next_to_a_free_cluster() {
    // Nothing is allocated beside `/solo`, so its growth takes the
    // neighbour rather than relocating: the stream entry on disk
    // must then carry the doubled data length.
    let mut volume = formatted();
    volume
        .mkdir("/solo", dirent::Stamps::epoch())
        .expect("the directory is created");
    let cluster_bytes = volume.geometry().cluster_bytes();
    for index in 0..60_u32 {
        let name = format!("/solo/f{index:03}.bin");
        volume
            .create_file(&name, 0, dirent::Stamps::epoch())
            .expect("the file is created");
    }

    let listing = volume.list_dir("/solo").expect("the directory lists");
    assert_eq!(listing.len(), 60, "every entry survives the growth");
    let root = volume.list_dir("/").expect("the root lists");
    let solo = root.first().expect("solo is listed");
    assert_eq!(
        solo.size,
        2 * cluster_bytes,
        "the on-disk stream length moved with the in-place extension"
    );
}

#[test]
fn a_relocation_copy_and_a_sparse_gap_survive_the_chunk_loop() {
    // Both spans here are larger than `COPY_CHUNK_BYTES`, so the copy
    // and the zero fill each iterate more than once. The single-chunk
    // sizes the other tests use cannot tell the loop body from a
    // whole-span `vec!`.
    // A larger heap than the default fixture: the sparse gap, the
    // payload and the relocation copy all have to fit at once.
    let store = VecVolume::new(32 * MIB, 512).expect("a thirty-two mebibyte store");
    let options = format::FormatOptions::new(SERIAL);
    let mut volume = Exfat::format(store, &options).expect("the formatter accepts this store");
    let cluster = volume.geometry().cluster_bytes() as usize;

    // A write that jumps three megabytes over untouched heap: the gap
    // is zero filled through the loop. This runs first, while the heap
    // still has one contiguous run that long.
    volume
        .create_file("/sparse.bin", 0, dirent::Stamps::epoch())
        .expect("the sparse file is created");
    volume
        .write_at("/sparse.bin", 0, b"head")
        .expect("the near write lands");
    let far = 3 * 1024 * 1024u64;
    volume
        .write_at("/sparse.bin", far, b"tail")
        .expect("the far write lands");
    let bytes = volume.read_file("/sparse.bin").expect("read back");
    assert_eq!(bytes.len() as u64, far + 4, "the size is the write's end");
    assert_eq!(&bytes[..4], b"head");
    assert_eq!(
        &bytes[4..far as usize],
        vec![0u8; far as usize - 4],
        "the jumped gap is zero"
    );
    assert_eq!(&bytes[far as usize..], b"tail");

    // A 2 MiB file followed by a gate: growing it cannot adopt the
    // next cluster, so the relocation copies the whole payload.
    let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    volume
        .create_file("/big.bin", payload.len() as u64, dirent::Stamps::epoch())
        .expect("the file is created");
    let half = payload.len() / 2;
    volume
        .write_at("/big.bin", 0, &payload[..half])
        .expect("the first half goes down");
    volume
        .write_at("/big.bin", half as u64, &payload[half..])
        .expect("the second half goes down");
    volume
        .create_file("/gate.bin", cluster as u64, dirent::Stamps::epoch())
        .expect("the gate is created");
    volume
        .write_at("/gate.bin", 0, &[0x00; 512])
        .expect("the gate is filled");
    let tail = [0xA5u8; 64];
    volume
        .write_at("/big.bin", payload.len() as u64, &tail)
        .expect("the relocating write lands");
    let mut expected = payload.clone();
    expected.extend_from_slice(&tail);
    assert_eq!(
        volume.read_file("/big.bin").expect("read back"),
        expected,
        "the relocated copy keeps every byte"
    );
}

#[test]
fn an_empty_file_reads_as_no_bytes() {
    let mut volume = formatted();
    volume
        .create_file("/empty.bin", 0, dirent::Stamps::epoch())
        .expect("the empty file is created");
    assert_eq!(
        stream_entry(&volume, "/empty.bin").0,
        0,
        "an empty file owns no cluster"
    );
    let bytes = volume
        .read_file("/empty.bin")
        .expect("the empty file reads");
    assert!(
        bytes.is_empty(),
        "an empty file has no bytes, got {bytes:?}"
    );
}

#[test]
fn a_write_failure_during_growth_rolls_the_ledger_back() {
    let store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
    let mut volume = Exfat::format(Flaky::new(store), &format::FormatOptions::new(SERIAL))
        .expect("the formatter accepts this store");
    volume
        .create_file("/grow.bin", 0, dirent::Stamps::epoch())
        .expect("the empty file is created");
    let before_free = volume.free_bytes();
    let cluster_bytes = volume.geometry().cluster_bytes();

    volume.volume.fail_after.set(Some(0));
    let payload = vec![0x5A_u8; usize::try_from(2 * cluster_bytes).expect("two clusters")];
    let error = volume
        .write_at("/grow.bin", 0, &payload)
        .expect_err("the injected write failure refuses the growth");
    assert!(error.to_string().contains("injected"), "{error}");
    volume.volume.fail_after.set(None);

    assert_eq!(volume.free_bytes(), before_free, "the ledger is restored");
    let listed = volume.list_dir("/").expect("the root lists");
    assert_eq!(listed.len(), 1, "the file entry survives");
    assert_eq!(listed[0].size, 0, "the refused growth publishes no length");
    assert!(
        volume
            .read_file("/grow.bin")
            .expect("the empty file reads")
            .is_empty(),
        "the refused growth leaves no data behind"
    );

    volume
        .write_at("/grow.bin", 0, &payload)
        .expect("the retry succeeds");
    assert_eq!(
        volume.read_file("/grow.bin").expect("the retry reads"),
        payload
    );
}

#[test]
fn a_write_failure_midway_rolls_the_ledger_back() {
    let store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
    let mut volume = Exfat::format(Flaky::new(store), &format::FormatOptions::new(SERIAL))
        .expect("the formatter accepts this store");
    let before_free = volume.free_bytes();
    let bitmap_first = volume.bitmap.first_cluster();
    let bitmap_at = volume
        .geometry
        .cluster_offset(bitmap_first)
        .expect("the bitmap cluster has an offset");
    let span = volume.bitmap.bytes().len();
    let mut before = vec![0_u8; span];
    volume
        .volume
        .read_exact_at(bitmap_at, &mut before)
        .expect("the bitmap reads");

    volume.volume.fail_after.set(Some(0));
    let error = volume
        .create_file("/lost.bin", 8192, dirent::Stamps::epoch())
        .expect_err("the injected write failure refuses the create");
    assert!(error.to_string().contains("injected"), "{error}");
    volume.volume.fail_after.set(None);

    assert_eq!(volume.free_bytes(), before_free, "the ledger is restored");
    assert!(
        volume.list_dir("/").expect("the root lists").is_empty(),
        "no entry survives the refused create"
    );
    volume.flush().expect("the bitmap writes back");
    let mut after = vec![0_u8; span];
    volume
        .volume
        .read_exact_at(bitmap_at, &mut after)
        .expect("the bitmap reads");
    assert_eq!(after, before, "the flushed bitmap is byte-identical");

    volume
        .create_file("/kept.bin", 8192, dirent::Stamps::epoch())
        .expect("the retry succeeds");
    let cluster_bytes = volume.geometry().cluster_bytes();
    assert_eq!(
        volume.free_bytes(),
        before_free - 2 * cluster_bytes,
        "two clusters are claimed by the retry"
    );
}

#[test]
fn a_torn_set_is_skipped_not_a_poisoned_directory() {
    let mut volume = flaky_formatted();
    let before_free = volume.free_bytes();
    // A 4 KiB file writes its cluster (if the allocator zeroes
    // it), then the dormant lead, the stream, the name and finally
    // the lead again. Failing on the last write leaves the whole set
    // on disk with its lead still deactivated -- exactly the state a
    // power cut during a create produces.
    volume.volume.writes.set(0);
    volume.volume.fail_after.set(Some(3));
    let error = volume
        .create_file("/torn.bin", 4096, dirent::Stamps::epoch())
        .expect_err("the injected write failure refuses the create");
    assert!(error.to_string().contains("injected"), "{error:?}");
    volume.volume.fail_after.set(None);

    assert_eq!(volume.free_bytes(), before_free, "the ledger is restored");
    assert!(
        volume
            .list_dir("/")
            .expect("the root still parses")
            .is_empty(),
        "a deactivated set is skipped, not a checksum failure"
    );

    // The bytes really are the deleted shape, not never-written.
    let cluster_bytes = usize::try_from(volume.geometry.cluster_bytes()).expect("fits");
    let root_first = volume
        .geometry
        .cluster_offset(volume.geometry.root_cluster)
        .expect("the root has an offset");
    let mut root = vec![0_u8; cluster_bytes];
    volume
        .volume
        .read_exact_at(root_first, &mut root)
        .expect("the root reads");
    let listing = dirent::parse_dir_listing(&root).expect("the torn root parses");
    let lead = listing.terminator_slot;
    assert_eq!(
        root.get(lead * 32).copied(),
        Some(dirent::ENTRY_IN_USE & 0x7F),
        "the lead slot is a deleted entry"
    );

    volume
        .create_file("/kept.bin", 4096, dirent::Stamps::epoch())
        .expect("the retry succeeds");
    assert_eq!(volume.list_dir("/").expect("the root lists").len(), 1);
}

#[test]
fn a_rolled_back_root_growth_puts_the_root_chain_back() {
    let mut volume = flaky_formatted();
    let slots = usize::try_from(volume.geometry.cluster_bytes() / 32).expect("fits");
    // The root already holds its two system entries plus the
    // end-of-directory marker, and every create takes three slots
    // (file, stream and one name entry -- an 8.3 name still carries
    // a 0xC1), so this fills the cluster exactly and leaves no slot
    // for the next set: the create below has to grow the chain.
    let fitting = (slots.saturating_sub(3)) / 3 + 1;
    for index in 0..fitting {
        volume
            .create_file(&format!("/f{index:03}.bin"), 0, dirent::Stamps::epoch())
            .expect("the root fills");
    }
    let root_cluster = volume.geometry.root_cluster;
    assert_eq!(
        volume
            .fat_entry(root_cluster)
            .expect("the root chain reads"),
        FAT_END_OF_CHAIN,
        "a full root still ends at its last cluster"
    );
    let before_free = volume.free_bytes();
    let before_listing = volume.list_dir("/").expect("the root lists").len();

    // The growth writes: the new cluster (0), its end-of-chain (1),
    // the link on the tail (2), then the set's dormant lead (3),
    // where the failure lands -- after both FAT words.
    volume.volume.writes.set(0);
    volume.volume.fail_after.set(Some(3));
    let error = volume
        .create_file("/grow.bin", 0, dirent::Stamps::epoch())
        .expect_err("the injected write failure refuses the create");
    assert!(error.to_string().contains("injected"), "{error}");
    volume.volume.fail_after.set(None);

    assert_eq!(volume.free_bytes(), before_free, "the ledger is restored");
    assert_eq!(
        volume.list_dir("/").expect("the root lists").len(),
        before_listing,
        "no entry survives the refused create"
    );
    assert_eq!(
        volume
            .fat_entry(root_cluster)
            .expect("the root chain reads"),
        FAT_END_OF_CHAIN,
        "the rollback puts the old end-of-chain back: a live root must not point at a freed cluster"
    );

    // The next create grows the root again, cleanly.
    volume
        .create_file("/grow.bin", 0, dirent::Stamps::epoch())
        .expect("the retry grows the root");
    assert_eq!(
        volume.list_dir("/").expect("the root lists").len(),
        before_listing + 1
    );
}

#[test]
fn a_formatted_volume_opens_and_lists_back() {
    let mut volume = formatted();
    volume
        .mkdir("/docs", dirent::Stamps::epoch())
        .expect("the directory is created");
    volume
        .create_file("/docs/a.txt", 4096, dirent::Stamps::epoch())
        .expect("the file is created");
    volume.flush().expect("the volume flushes");
    let bytes = volume.volume.bytes().to_vec();
    let mut store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
    store
        .write_all_at(0, &bytes)
        .expect("the image copies back");
    let reopened = Exfat::open(store).expect("the formatter's image opens");
    assert_eq!(reopened.free_bytes(), volume.free_bytes());
    assert_eq!(
        reopened
            .list_dir("/docs")
            .expect("the directory lists")
            .len(),
        1
    );
}

#[test]
fn open_refuses_a_damaged_boot_region_checksum() {
    let mut volume = formatted();
    volume.flush().expect("the volume flushes");
    let sector = usize::try_from(volume.geometry.sector_size).expect("fits");
    let mut bytes = volume.volume.bytes().to_vec();
    // Flip one byte inside the boot sector proper: the stored
    // checksum in sector 11 no longer describes it.
    bytes[sector + 123] ^= 0x01;
    let mut store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
    store
        .write_all_at(0, &bytes)
        .expect("the image copies back");
    let Err(error) = Exfat::open(store) else {
        panic!("a damaged boot region must not open");
    };
    let text = error.to_string();
    assert!(text.contains("checksum"), "{text}");
}

#[test]
fn open_refuses_a_damaged_checksum_sector() {
    let mut volume = formatted();
    volume.flush().expect("the volume flushes");
    let sector = usize::try_from(volume.geometry.sector_size).expect("fits");
    let mut bytes = volume.volume.bytes().to_vec();
    // Sector 11 is the checksum sector, and its *first* word is
    // the one `open` compares against the accumulated checksum (the
    // sector repeats it for the region's other copies; flipping a
    // repetition is invisible to a reader that only reads word 0,
    // which is why the corruption goes in the first word).
    bytes[11 * sector] ^= 0x40;
    let mut store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
    store
        .write_all_at(0, &bytes)
        .expect("the image copies back");
    let Err(error) = Exfat::open(store) else {
        panic!("a damaged boot region must not open");
    };
    assert!(error.to_string().contains("checksum"), "{error}");
}

#[test]
fn a_fragmented_directory_reads_its_chain_and_refuses_growth() {
    // A directory grown in place stays contiguous. Turn the same
    // bytes into a FAT-chained directory by linking the run and
    // clearing NoFatChain, the shape another implementation may
    // write; reading it must still work, and growing it must refuse
    // rather than write a stream entry its FAT chain does not back.
    let mut volume = formatted();
    volume
        .mkdir("/d", dirent::Stamps::epoch())
        .expect("the directory is created");
    let slots = usize::try_from(volume.geometry().cluster_bytes() / 32).expect("slots");
    let per_set = 3; // file, stream, one name entry
    let count = slots / per_set + 4;
    for index in 0..count {
        volume
            .create_file(&format!("/d/f{index:03}.bin"), 0, dirent::Stamps::epoch())
            .expect("the files fit after a growth");
    }
    let root = volume.root_level().expect("the root reads");
    let levels = volume.walk(&["d".to_owned()]).expect("the directory walks");
    let level = levels.last().expect("the directory level");
    assert!(level.contiguous, "the fixture starts contiguous");
    let chain = level.content.chain.clone();
    assert_eq!(chain.len(), 2, "the fixture grew to two clusters");
    volume
        .set_fat_entry(chain[0], chain[1])
        .expect("the link lands");
    volume
        .set_fat_entry(chain[1], FAT_END_OF_CHAIN)
        .expect("the end lands");
    let set_slots = level.own_set_slots.clone().expect("the set is known");
    let mut images: Vec<[u8; 32]> = set_slots
        .iter()
        .map(|slot| {
            let mut image = [0_u8; 32];
            let at = root
                .content
                .slot_address(volume.geometry(), *slot)
                .expect("the slot has an address");
            volume
                .volume
                .read_exact_at(at, &mut image)
                .expect("the slot reads");
            image
        })
        .collect();
    let stream = images.get_mut(1).expect("the set has a stream slot");
    let flags = stream.get(1).copied().expect("the flags are in range");
    *stream.get_mut(1).expect("the flags are in range") = flags & !0x02;
    let checksum = dirent::set_checksum(&images);
    images
        .first_mut()
        .expect("the set has a lead")
        .get_mut(2..4)
        .expect("the checksum field is in range")
        .copy_from_slice(&checksum.to_le_bytes());
    for (slot, image) in set_slots.iter().zip(images.iter()) {
        let at = root
            .content
            .slot_address(volume.geometry(), *slot)
            .expect("the slot has an address");
        volume
            .volume
            .write_all_at(at, image)
            .expect("the slot writes");
    }
    volume.flush().expect("the image flushes");

    let mut reopened = Exfat::open(volume.volume.clone()).expect("the image reopens");
    let listed = reopened.list_dir("/d").expect("a chained directory lists");
    assert_eq!(listed.len(), count, "every entry survives the chain read");

    // Fill the two clusters, then one more set has to grow the
    // directory - which a fragmented allocation cannot do.
    let target_sets = (2 * slots) / per_set;
    let mut created = count;
    while created < target_sets {
        reopened
            .create_file(&format!("/d/f{created:03}.bin"), 0, dirent::Stamps::epoch())
            .expect("the directory still has slots");
        created += 1;
    }
    let error = reopened
        .create_file("/d/overflow.bin", 0, dirent::Stamps::epoch())
        .expect_err("a fragmented directory cannot grow");
    assert!(
        error.to_string().contains("fragmented"),
        "the refusal names the fragmentation: {error}"
    );
}

#[test]
fn a_path_naming_the_root_is_not_a_leaf() {
    let mut volume = formatted();
    let error = volume
        .mkdir("/", dirent::Stamps::epoch())
        .expect_err("the root cannot be created");
    assert!(error.to_string().contains("root"), "{error}");
}

#[test]
fn a_written_file_round_trips_through_a_zero_gap() {
    let mut volume = formatted();
    let cluster_bytes = volume.geometry().cluster_bytes();
    volume
        .mkdir("/docs", dirent::Stamps::epoch())
        .expect("the directory is created");
    volume
        .create_file("/docs/pattern.bin", cluster_bytes, dirent::Stamps::epoch())
        .expect("the file claims exactly one cluster");
    // Garble the allocated run and its two neighbours before any
    // byte of content exists: a fresh store reads zeros everywhere,
    // so only bytes write_at itself puts down can explain a zero
    // readback below.
    let (first, data_length, valid) = stream_entry(&volume, "/docs/pattern.bin");
    assert_eq!(
        data_length, cluster_bytes,
        "the size hint is the DataLength"
    );
    assert_eq!(valid, 0, "a fresh file carries no valid data");
    let garble = vec![0xAA_u8; usize::try_from(3 * cluster_bytes).expect("fits")];
    let at = volume
        .geometry()
        .cluster_offset(first)
        .expect("the run's offset reads");
    volume
        .volume
        .write_all_at(at, &garble)
        .expect("the garble lands");

    // Write at 0, then one further past the allocation with a gap
    // between the two writes: the gap must read back zeros.
    let head: Vec<u8> = (0..cluster_bytes / 2)
        .map(|step| (step % 251) as u8)
        .collect();
    volume
        .write_at("/docs/pattern.bin", 0, &head)
        .expect("the head lands inside the allocation");
    let tail_offset = 3 * cluster_bytes + 123;
    let tail: Vec<u8> = (0..50u64).map(|step| ((step % 97) + 7) as u8).collect();
    volume
        .write_at("/docs/pattern.bin", tail_offset, &tail)
        .expect("the tail grows the allocation");

    let read = volume
        .read_file("/docs/pattern.bin")
        .expect("the file reads back");
    assert_eq!(
        read.len() as u64,
        tail_offset + tail.len() as u64,
        "exactly the valid bytes come back"
    );
    assert_eq!(&read[..head.len()], &head[..], "the head survives");
    let tail_at = usize::try_from(tail_offset).expect("fits");
    assert!(
        read[head.len()..tail_at].iter().all(|&byte| byte == 0),
        "the gap the write jumped over reads back as zeros"
    );
    assert_eq!(&read[tail_at..], &tail[..], "the tail lands at its offset");

    // The listing reports the new size, and the stream entry kept
    // its first cluster: the growth adopted free neighbours.
    let (first_after, data_after, valid_after) = stream_entry(&volume, "/docs/pattern.bin");
    assert_eq!(
        first_after, first,
        "the growth adopted the neighbours in place"
    );
    assert_eq!(
        data_after,
        tail_offset + tail.len() as u64,
        "DataLength ends at the write, not at the allocation"
    );
    assert_eq!(valid_after, tail_offset + tail.len() as u64);
    let docs = volume.list_dir("/docs").expect("the directory lists");
    assert_eq!(
        docs.first().expect("the file lists").size,
        tail_offset + tail.len() as u64,
        "the listing reports the bytes written"
    );
}

#[test]
fn a_write_past_the_allocation_grows_in_place_with_free_neighbours() {
    let mut volume = formatted();
    let cluster_bytes = volume.geometry().cluster_bytes();
    // Filler allocations come first, so the target sits mid-heap
    // with the clusters behind it free deliberately, not by
    // low-address luck.
    for index in 0..10 {
        volume
            .create_file(
                &format!("/filler{index:02}.bin"),
                3 * cluster_bytes,
                dirent::Stamps::epoch(),
            )
            .expect("a filler claims three clusters");
    }
    volume
        .create_file("/target.bin", cluster_bytes, dirent::Stamps::epoch())
        .expect("the target claims exactly one cluster");
    let (first, data_length, valid) = stream_entry(&volume, "/target.bin");
    assert_eq!(data_length, cluster_bytes);
    assert_eq!(valid, 0);
    assert_ne!(first, 0, "the fixture needs a real run to grow");
    assert!(
        volume
            .bitmap
            .is_free(first.checked_add(1).expect("fits"))
            .expect("the neighbour is inside the heap"),
        "the fixture must leave the next cluster free for adoption"
    );

    let free_before = volume.free_bytes();
    // Two clusters of content one allocation-past the end: the
    // growth adopts both neighbours in place.
    let added = vec![0x5E_u8; usize::try_from(2 * cluster_bytes).expect("fits")];
    volume
        .write_at("/target.bin", cluster_bytes, &added)
        .expect("the writer adopted the free neighbours");

    let (first_after, data_after, valid_after) = stream_entry(&volume, "/target.bin");
    assert_eq!(
        first_after, first,
        "in-place growth keeps the first cluster"
    );
    assert_eq!(data_after, 3 * cluster_bytes);
    assert_eq!(valid_after, 3 * cluster_bytes);
    assert_eq!(
        free_before - volume.free_bytes(),
        2 * cluster_bytes,
        "the free count dropped by exactly the adopted clusters"
    );
    let read = volume
        .read_file("/target.bin")
        .expect("the file reads back");
    assert_eq!(read.len() as u64, 3 * cluster_bytes);
    assert!(
        read[..cluster_bytes as usize].iter().all(|&byte| byte == 0),
        "the adopted-gap bytes read back as zeros"
    );
    assert_eq!(&read[cluster_bytes as usize..], &added[..]);
    assert_eq!(
        volume.list_dir("/").expect("the root lists").len(),
        11,
        "the fillers and the target all survive the growth"
    );
}

#[test]
fn a_write_past_taken_neighbours_relocates_the_run_and_frees_the_old() {
    let mut volume = formatted();
    let cluster_bytes = volume.geometry().cluster_bytes();
    volume
        .create_file("/owner.bin", cluster_bytes, dirent::Stamps::epoch())
        .expect("the owner claims one cluster");
    // The gate sits exactly behind the owner: the owners free
    // neighbours are taken, so the growth must relocate.
    volume
        .create_file("/gate.bin", 2 * cluster_bytes, dirent::Stamps::epoch())
        .expect("the gate claims two clusters");
    let (first, _, _) = stream_entry(&volume, "/owner.bin");
    let (gate, _, _) = stream_entry(&volume, "/gate.bin");
    assert_eq!(
        gate,
        first.checked_add(1).expect("fits"),
        "the fixture pins the gate right behind the owner"
    );
    // The owner gets real content first, so the relocation has
    // existing ValidDataLength bytes to move.
    let head: Vec<u8> = (0..100u64)
        .map(|step| ((step * 7 + 3) % 251) as u8)
        .collect();
    volume
        .write_at("/owner.bin", 0, &head)
        .expect("the head lands inside the allocation");

    let free_before = volume.free_bytes();
    // Two clusters one allocation-past the end: with the
    // neighbours taken, the whole run relocates.
    let body = vec![0x3C_u8; usize::try_from(2 * cluster_bytes).expect("fits")];
    volume
        .write_at("/owner.bin", cluster_bytes, &body)
        .expect("the writer relocated the run");

    let (first_after, data_after, valid_after) = stream_entry(&volume, "/owner.bin");
    assert_ne!(
        first_after, first,
        "the stream entry moved to the fresh run"
    );
    assert_eq!(data_after, 3 * cluster_bytes);
    assert_eq!(valid_after, 3 * cluster_bytes);
    let read = volume
        .read_file("/owner.bin")
        .expect("the relocated data reads back");
    assert_eq!(read.len() as u64, 3 * cluster_bytes);
    assert_eq!(
        &read[..head.len()],
        &head[..],
        "the copied valid bytes survive the move"
    );
    assert!(
        read[head.len()..cluster_bytes as usize]
            .iter()
            .all(|&byte| byte == 0),
        "the zero region inside the fresh run reads back as zeros"
    );
    assert_eq!(
        &read[cluster_bytes as usize..],
        &body[..],
        "the written tail lands at its offset in the fresh run"
    );
    // The old cluster is free again, and the free count moved by
    // exactly the growth: three clusters claimed, one released.
    assert!(
        volume
            .bitmap
            .is_free(first)
            .expect("the old cluster is inside the heap"),
        "the released old run returns to the pool"
    );
    assert_eq!(
        free_before - volume.free_bytes(),
        (3 - 1) * cluster_bytes,
        "the free count reflects three claimed and one released clusters"
    );
    // And the gate kept both its clusters untouched.
    let (gate_after, gate_data, gate_valid) = stream_entry(&volume, "/gate.bin");
    assert_eq!(gate_after, gate, "a relocation does not move other files");
    assert_eq!(gate_data, 2 * cluster_bytes);
    assert_eq!(gate_valid, 0);
}

#[test]
fn write_and_read_refusals_name_their_paths_and_numbers() {
    let mut volume = formatted();
    volume
        .mkdir("/adir", dirent::Stamps::epoch())
        .expect("the directory is created");

    // A directory refuses for both directions, with the path named.
    let error = volume
        .write_at("/adir", 0, b"x")
        .expect_err("a directory cannot be written");
    let text = error.to_string();
    assert!(
        text.contains("/adir") && text.contains("directory"),
        "{text}"
    );
    let error = volume
        .read_file("/adir")
        .expect_err("a directory cannot be read");
    let text = error.to_string();
    assert!(
        text.contains("/adir") && text.contains("directory"),
        "{text}"
    );

    // A missing path refuses, path named, for both directions.
    let error = volume
        .write_at("/ghost.txt", 0, b"x")
        .expect_err("there is nothing to write into");
    assert!(error.to_string().contains("ghost.txt"), "{error}");
    let error = volume
        .read_file("/ghost.txt")
        .expect_err("there is nothing to read");
    assert!(error.to_string().contains("ghost.txt"), "{error}");

    // A write past the volume end refuses, naming the write's end
    // and the heap's byte capacity, and leaves nothing behind.
    // The file must exist first: a missing path refuses before
    // the growth math even runs.
    let cluster_bytes = volume.geometry().cluster_bytes();
    let capacity = u64::from(volume.geometry().cluster_count) * cluster_bytes;
    volume
        .create_file("/end.bin", 0, dirent::Stamps::epoch())
        .expect("the empty end-marker file is created");
    let free_before = volume.free_bytes();
    let error = volume
        .write_at("/end.bin", capacity, b"!")
        .expect_err("the write would end past the volume");
    let text = error.to_string();
    assert!(
        text.contains(&(capacity + 1).to_string()) && text.contains(&capacity.to_string()),
        "the refusal names the write's end and the capacity: {text}"
    );
    assert_eq!(
        volume.free_bytes(),
        free_before,
        "the refused write moved no allocation"
    );
    assert_eq!(
        names(&volume.list_dir("/").expect("the root lists")),
        ["adir", "end.bin"],
        "the refused write left exactly what was there"
    );

    // A stream entry whose valid length claims past its data
    // length (hand-made damage) refuses, both numbers named.
    volume
        .create_file("/liar.bin", cluster_bytes, dirent::Stamps::epoch())
        .expect("the file is created");
    patch_valid_length(&mut volume, "/liar.bin", cluster_bytes + 1);
    let error = volume
        .read_file("/liar.bin")
        .expect_err("valid cannot claim past data");
    let text = error.to_string();
    assert!(
        text.contains(&(cluster_bytes + 1).to_string())
            && text.contains(&cluster_bytes.to_string()),
        "the refusal names both lengths: {text}"
    );
}

#[test]
fn a_zero_length_write_is_a_no_op_down_to_the_stored_bytes() {
    let mut volume = formatted();
    volume
        .create_file(
            "/still.bin",
            volume.geometry().cluster_bytes(),
            dirent::Stamps::epoch(),
        )
        .expect("the sized file is created");
    volume
        .create_file("/empty.bin", 0, dirent::Stamps::epoch())
        .expect("the empty file is created");
    let listing = volume.list_dir("/").expect("the root lists");
    let before = volume.volume.bytes().to_vec();

    // A zero-length write at any offset (even far past the
    // allocation) neither allocates, writes, nor rewrites an entry
    // — and a zero-length write to a missing path still resolves
    // first, so it refuses rather than silently succeeding.
    volume
        .write_at("/still.bin", 1 << 30, b"")
        .expect("the no-op write succeeds");
    volume
        .write_at("/empty.bin", 0, b"")
        .expect("the no-op write into the empty file succeeds");
    let error = volume
        .write_at("/ghost.txt", 0, b"")
        .expect_err("resolution comes before the no-op");
    assert!(error.to_string().contains("ghost.txt"), "{error}");

    assert_eq!(volume.volume.bytes(), &before[..], "not one byte moved");
    assert_eq!(
        volume.list_dir("/").expect("the root lists"),
        listing,
        "the listing is untouched"
    );
}

/// A stamp set distinct from the epoch fixture: three different
/// moments, each with its own tenth-of-second and UTC-offset byte
/// — so a test can tell one swapped field from a dropped one, and
/// tell either from "nothing changed".
fn later_stamps() -> dirent::Stamps {
    dirent::Stamps {
        create: dirent::Stamp {
            tenths: 7,
            utc_offset: 0x80,
            ..dirent::Stamp::from_ymdhms(2026, 11, 1, 9, 0, 0).expect("valid ymdhms")
        },
        modify: dirent::Stamp {
            tenths: 148,
            utc_offset: 0x40,
            ..dirent::Stamp::from_ymdhms(2026, 11, 1, 10, 30, 2).expect("valid ymdhms")
        },
        access: dirent::Stamp {
            // A tenth byte deliberately left unrepresentable on
            // disk: the format defines no access 10 ms field, so
            // storing 199 there must change nothing a reader sees.
            tenths: 199,
            utc_offset: 0x15,
            ..dirent::Stamp::from_ymdhms(2026, 11, 1, 23, 59, 58).expect("valid ymdhms")
        },
    }
}

/// The stamps from `times` as the on-disk reader
/// ([`dirent::parse_dir_listing`] over the set's slots) reports
/// them back: everything round-trips except the access stamp's
/// tenth byte, which the format gives no field to — readers
/// always see zero there.
fn as_stored(times: dirent::Stamps) -> dirent::Stamps {
    dirent::Stamps {
        create: times.create,
        modify: times.modify,
        access: dirent::Stamp {
            tenths: 0,
            ..times.access
        },
    }
}

/// The entry set of the leaf at `path`, read back from its
/// parent's live directory content: the parsed entry (stamps
/// included) plus the raw 32 bytes of its lead slot, which the
/// stamp tests pin field-by-field.
#[track_caller]
fn set_entry(volume: &Exfat<VecVolume>, path: &str) -> (dirent::DirEntry, [u8; 32]) {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let leaf = parts.last().copied().expect("the path has a leaf");
    let parents: Vec<String> = parts
        .iter()
        .take(parts.len().saturating_sub(1))
        .map(|part| (*part).to_owned())
        .collect();
    let levels = volume.walk(&parents).expect("the parent directory walks");
    let parent = levels.last().expect("the parent is in the walk");
    let listing = dirent::parse_dir_listing(&parent.content.bytes).expect("the listing parses");
    let cluster_bytes = usize::try_from(volume.geometry().cluster_bytes())
        .expect("a cluster fits this machine's usize");
    for (entry, start) in listing.entries.iter().zip(listing.set_starts.iter()) {
        if dirent::upcase_name(&entry.name) != dirent::upcase_name(leaf) {
            continue;
        }
        let lead = slot_image(&parent.content, cluster_bytes, *start).expect("the lead slot reads");
        return (entry.clone(), lead);
    }
    panic!("the entry {path} is not in its parent's listing");
}

#[test]
fn set_times_stamps_a_file_set() {
    let mut volume = formatted();
    volume
        .create_file("/file.bin", 0, dirent::Stamps::epoch())
        .expect("the file is created");
    let times = later_stamps();

    volume
        .set_times("/file.bin", times)
        .expect("the stamp rewrite lands");

    let (entry, lead) = set_entry(&volume, "/file.bin");
    assert_eq!(
        entry.stamps.create, times.create,
        "the create stamp round-trips"
    );
    assert_eq!(
        entry.stamps.modify, times.modify,
        "the modify stamp round-trips"
    );
    assert_eq!(
        entry.stamps.access,
        as_stored(times).access,
        "the access stamp keeps its date-time and offset; its tenth byte has no field on disk"
    );
    // Pin the raw tenth bytes too: exactly create at 20 and modify
    // at 21 — the offsets the reader derives the stamps from.
    assert_eq!(
        lead[20], times.create.tenths,
        "the create tenth lives at byte 20"
    );
    assert_eq!(
        lead[21], times.modify.tenths,
        "the modify tenth lives at byte 21"
    );
    assert_eq!(
        [lead[22], lead[23], lead[24]],
        [
            times.create.utc_offset,
            times.modify.utc_offset,
            times.access.utc_offset
        ],
        "all three utc offsets live at bytes 22, 23 and 24"
    );
}

#[test]
fn set_times_matches_case_and_names_a_long_set() {
    let mut volume = formatted();
    volume
        .create_file("/file.bin", 0, dirent::Stamps::epoch())
        .expect("the file is created");
    // A name of 29 UTF-16 units: its set needs two 0xC1 name slots
    // beside the file and stream slots, so the stamp resolution
    // must find the set's own window in a shape longer than the
    // minimum three slots.
    let long_name = "The Quick Brown Fox Jumps.txt";
    volume
        .create_file(&format!("/{long_name}"), 0, dirent::Stamps::epoch())
        .expect("the long-named file is created");
    let times = later_stamps();

    // Both lookups go through the case-insensitive up-case match
    // (the leaf given in a different case than the entry carries).
    volume
        .set_times("/FILE.BIN", times)
        .expect("the stamp lands");
    volume
        .set_times("/THE QUICK BROWN FOX JUMPS.TXT", times)
        .expect("the long set's stamp lands");

    for path in ["/file.bin", &format!("/{long_name}")] {
        let (entry, _) = set_entry(&volume, path);
        assert_eq!(
            entry.stamps.create, times.create,
            "the create stamp round-trips at {path}"
        );
        assert_eq!(
            entry.stamps.modify, times.modify,
            "the modify stamp round-trips at {path}"
        );
        assert_eq!(
            entry.stamps.access,
            as_stored(times).access,
            "the access stamp keeps its date-time and offset at {path}"
        );
    }

    // The long name's set really is longer than the minimum: file
    // + stream + two 0xC1 name slots.
    let levels = volume.walk(&[]).expect("the root walks");
    let parent = levels.last().expect("the walk holds the root");
    let listing = dirent::parse_dir_listing(&parent.content.bytes).expect("the root parses");
    for (index, start) in listing.set_starts.iter().copied().enumerate() {
        let entry = listing
            .entries
            .get(index)
            .expect("the set's start has an entry");
        if entry.name == long_name {
            let set_end = listing
                .set_starts
                .get(index + 1)
                .copied()
                .unwrap_or(listing.terminator_slot);
            assert_eq!(
                (start..set_end).count(),
                4,
                "two 0xC1 name slots carry the 29 units"
            );
            break;
        }
    }
    assert_eq!(
        names(&volume.list_dir("/").expect("the root lists")),
        ["file.bin", long_name],
        "the case-preserved names still list"
    );
}

#[test]
fn set_times_stamps_a_directory_set() {
    let mut volume = formatted();
    volume
        .mkdir("/docs", dirent::Stamps::epoch())
        .expect("the directory is created");
    let times = later_stamps();

    volume
        .set_times("/docs", times)
        .expect("the stamp rewrite lands");

    let (entry, lead) = set_entry(&volume, "/docs");
    assert!(entry.is_dir, "the stamped set is still a directory");
    assert_eq!(
        entry.stamps.create, times.create,
        "the create stamp round-trips"
    );
    assert_eq!(
        entry.stamps.modify, times.modify,
        "the modify stamp round-trips"
    );
    assert_eq!(
        entry.stamps.access,
        as_stored(times).access,
        "the access stamp keeps its date-time and offset"
    );
    assert_eq!(lead[20], times.create.tenths, "the create tenth survives");
    assert_eq!(lead[21], times.modify.tenths, "the modify tenth survives");
    assert_eq!(
        lead[24], times.access.utc_offset,
        "the access offset survives"
    );
}

#[test]
fn set_times_survives_a_reopen_round_trip() {
    let mut volume = formatted();
    volume
        .mkdir("/docs", dirent::Stamps::epoch())
        .expect("the directory is created");
    volume
        .create_file("/docs/notes.txt", 0, dirent::Stamps::epoch())
        .expect("the file is created");
    let times = later_stamps();
    volume
        .set_times("/docs", times)
        .expect("the directory's stamps land");
    volume
        .set_times("/docs/notes.txt", times)
        .expect("the file's stamps land");

    // The listings still report name, size and shape exactly as
    // before: stamps are not part of what a listing shows.
    let root = volume.list_dir("/").expect("the root lists");
    assert_eq!(names(&root), ["docs"]);
    assert!(root[0].is_dir, "the root's entry is still a directory");
    assert_eq!(
        root[0].size,
        volume.geometry().cluster_bytes(),
        "the directory reports its whole allocation"
    );
    assert_eq!(
        names(&volume.list_dir("/docs").expect("the directory lists")),
        ["notes.txt"]
    );

    volume.flush().expect("the volume flushes");
    let bytes = volume.volume.bytes().to_vec();
    let mut store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
    store
        .write_all_at(0, &bytes)
        .expect("the image copies back");
    let reopened = Exfat::open(store).expect("the stamped image opens");
    for path in ["/docs", "/docs/notes.txt"] {
        let (entry, _) = set_entry(&reopened, path);
        assert_eq!(
            entry.stamps.create, times.create,
            "the create stamp survives at {path}"
        );
        assert_eq!(
            entry.stamps.modify, times.modify,
            "the modify stamp survives at {path}"
        );
        assert_eq!(
            entry.stamps.access,
            as_stored(times).access,
            "the access stamp survives at {path}"
        );
    }
}

#[test]
fn set_times_moves_only_the_stamp_fields() {
    let mut volume = formatted();
    volume
        .create_file(
            "/target.bin",
            volume.geometry().cluster_bytes(),
            dirent::Stamps::epoch(),
        )
        .expect("the file claims exactly one cluster");
    let stream_before = stream_entry(&volume, "/target.bin");
    let free_before = volume.free_clusters;

    let times = later_stamps();
    volume
        .set_times("/target.bin", times)
        .expect("the stamp rewrite lands");

    assert_eq!(
        stream_entry(&volume, "/target.bin"),
        stream_before,
        "the stream entry's cluster and lengths are untouched"
    );
    assert_eq!(
        volume.free_clusters, free_before,
        "no cluster moved for a stamp rewrite"
    );
    assert_eq!(
        names(&volume.list_dir("/").expect("the root lists")),
        ["target.bin"],
        "the entry still lists with its name"
    );
}

#[test]
fn set_times_refuses_the_root_and_a_missing_leaf() {
    let mut volume = formatted();
    volume
        .create_file("/kept.bin", 0, dirent::Stamps::epoch())
        .expect("the file is created");
    let times = later_stamps();

    let error = volume
        .set_times("/", times)
        .expect_err("the root cannot be stamped");
    let text = error.to_string();
    assert!(text.contains("root"), "the refusal names the root: {text}");
    assert!(text.contains("set_times"), "{text}");
    assert!(text.is_ascii(), "refusals stay ascii: {text}");

    let error = volume
        .set_times("/nope", times)
        .expect_err("a missing leaf cannot be stamped");
    let text = error.to_string();
    assert!(text.contains("/nope"), "the refusal names the path: {text}");
    assert!(text.is_ascii(), "refusals stay ascii: {text}");

    assert_eq!(
        names(&volume.list_dir("/").expect("the root lists")),
        ["kept.bin"],
        "the refused calls left exactly what was there"
    );
}

#[test]
fn a_write_at_never_moves_the_set_times() {
    let mut volume = formatted();
    volume
        .create_file("/doc.bin", 0, dirent::Stamps::epoch())
        .expect("the file is created");
    let times = later_stamps();
    volume
        .set_times("/doc.bin", times)
        .expect("the stamp rewrite lands");

    volume
        .write_at("/doc.bin", 0, b"payload")
        .expect("the write lands");
    assert_eq!(
        volume.read_file("/doc.bin").expect("the file reads"),
        b"payload",
        "the write reached the file"
    );

    let (entry, _) = set_entry(&volume, "/doc.bin");
    assert_eq!(
        entry.stamps.create, times.create,
        "the create stamp survived the write"
    );
    assert_eq!(
        entry.stamps.modify, times.modify,
        "the modify stamp survived the write"
    );
    assert_eq!(
        entry.stamps.access,
        as_stored(times).access,
        "the access stamp survived the write"
    );
    let (first, data, valid) = stream_entry(&volume, "/doc.bin");
    assert_ne!(first, 0, "the write allocated a run");
    assert_eq!(
        data,
        b"payload".len() as u64,
        "DataLength ends at the write"
    );
    assert_eq!(valid, b"payload".len() as u64, "ValidDataLength covers it");
}

// ------------------------------------------------------------------
// Labels: set_label
// ------------------------------------------------------------------

/// A formatted volume whose root carries a live "FURUS" label: the
/// variant `set_label` replaces, clears and refuses around (the
/// struct-literal options mirror the format.rs label test, pinning
/// this fixture's own serial).
fn labelled() -> Exfat<VecVolume> {
    let volume = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
    let options = format::FormatOptions {
        label: Some("FURUS".to_string()),
        volume_id: SERIAL,
        cluster_bytes: None,
    };
    Exfat::format(volume, &options).expect("the formatter accepts this store")
}

/// The raw 32 bytes of the root's `slot`-th slot.
#[track_caller]
fn root_slot(volume: &Exfat<VecVolume>, slot: usize) -> [u8; 32] {
    let root = volume.root_level().expect("the root reads");
    let cluster_bytes = usize::try_from(volume.geometry().cluster_bytes())
        .expect("a cluster fits this machine's usize");
    slot_image(&root.content, cluster_bytes, slot).expect("the slot reads")
}

/// The root's live label entry, found the raw way the volume code
/// scans for it (a lead byte of 0x83 before the terminator): the
/// slot it sits in and its 32 bytes. The slot index pins *where* a
/// label landed — slot 0 on a labelled format, behind the up-case
/// entry after an append, at the marker after a clear.
#[track_caller]
fn live_label(volume: &Exfat<VecVolume>) -> (usize, [u8; 32]) {
    let root = volume.root_level().expect("the root reads");
    let listing = dirent::parse_dir_listing(&root.content.bytes).expect("the listing parses");
    for slot in 0..listing.terminator_slot {
        let image = root_slot(volume, slot);
        if image[0] == format::ENTRY_VOLUME_LABEL {
            return (slot, image);
        }
    }
    panic!("the root has no live label entry");
}

/// The label text a 0x83 slot's bytes carry: count byte, then
/// UTF-16LE units.
fn label_text(image: &[u8]) -> String {
    let units: Vec<u16> = (0..usize::from(image[1]))
        .map(|step| u16::from_le_bytes([image[2 + step * 2], image[3 + step * 2]]))
        .collect();
    String::from_utf16(&units).expect("the label decodes")
}

/// A byte-copy reopen: the fixture's image, flushed, copied into a
/// fresh store and parsed back with `Exfat::open` — the round trip
/// the older reopen tests carry out inline.
#[track_caller]
fn reopened(volume: &mut Exfat<VecVolume>) -> Exfat<VecVolume> {
    volume.flush().expect("the volume flushes");
    let bytes = volume.volume.bytes().to_vec();
    let mut store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
    store
        .write_all_at(0, &bytes)
        .expect("the image copies back");
    Exfat::open(store).expect("the image opens")
}

#[test]
fn set_label_replaces_a_formatted_label_in_place() {
    let mut volume = labelled();
    volume
        .set_label(Some("HELLO"))
        .expect("the replacement lands");

    let (slot, image) = live_label(&volume);
    assert_eq!(slot, 0, "the live label is rewritten in its own slot");
    assert_eq!(
        image[0],
        format::ENTRY_VOLUME_LABEL,
        "the lead is a live label"
    );
    assert_eq!(
        usize::from(image[1]),
        "HELLO".encode_utf16().count(),
        "the count byte carries the unit count"
    );
    assert_eq!(label_text(&image), "HELLO", "the units decode back");
    assert!(
        image.iter().skip(12).all(|byte| *byte == 0),
        "past the units the slot is zero"
    );

    // The rewritten slot survives a reopen round trip, and the
    // listing walk still ends in an empty listing (labels never list).
    let volume = reopened(&mut volume);
    assert!(volume.list_dir("/").expect("the root lists").is_empty());
    assert_eq!(
        live_label(&volume),
        (slot, image),
        "the replaced label round-trips"
    );
}

#[test]
fn set_label_none_deletes_the_live_label_entry() {
    let mut volume = labelled();
    volume.set_label(None).expect("the clear lands");

    // The old label slot is the deleted shape: lead 0x03, then zeros.
    let image = root_slot(&volume, 0);
    assert_eq!(
        image[0],
        format::ENTRY_VOLUME_LABEL & !dirent::ENTRY_IN_USE,
        "the slot's lead carries the deleted label type"
    );
    assert!(
        image[1..].iter().all(|byte| *byte == 0),
        "count and units are zeroed"
    );

    // The walk still parses, ending at the same marker; the system
    // entries behind the deleted slot stay in place (and never list).
    let root = volume.root_level().expect("the root reads");
    let listing = dirent::parse_dir_listing(&root.content.bytes).expect("the walk parses");
    assert_eq!(
        listing.terminator_slot, 3,
        "the marker kept its slot behind the system entries"
    );
    assert_eq!(
        root_slot(&volume, 1)[0],
        format::ENTRY_BITMAP,
        "the bitmap entry stayed"
    );
    assert_eq!(
        root_slot(&volume, 2)[0],
        format::ENTRY_UP_CASE,
        "the up-case entry stayed"
    );
    assert_eq!(
        listing.total_slots,
        usize::try_from(volume.geometry().cluster_bytes()).expect("fits") / format::ENTRY_BYTES,
        "the capacity read is the cluster's slot count"
    );
    assert!(
        volume.list_dir("/").expect("the root lists").is_empty(),
        "the system entries (and the deleted label) never list"
    );

    // And the image still opens: the bitmap is found through the walk.
    let volume = reopened(&mut volume);
    assert!(volume.list_dir("/").expect("the root lists").is_empty());
}

#[test]
fn set_label_appends_behind_the_system_entries_when_there_was_none() {
    let mut volume = formatted();
    volume
        .set_label(Some("APPENDED"))
        .expect("the append lands");

    let (slot, image) = live_label(&volume);
    assert_eq!(
        slot, 2,
        "the label took the marker's slot behind the bitmap (0) and up-case (1) entries"
    );
    assert_eq!(image[0], format::ENTRY_VOLUME_LABEL);
    assert_eq!(label_text(&image), "APPENDED");

    // The marker moved one slot back: the slot behind the label is
    // the fresh end-of-directory zeros.
    let marker = root_slot(&volume, slot + 1);
    assert!(
        marker.iter().all(|byte| *byte == 0),
        "the marker moved behind the label"
    );

    // A single-slot entry behind the system entries stays walkable
    // across a reopen, and the bitmap is still found through it.
    let volume = reopened(&mut volume);
    assert!(volume.list_dir("/").expect("the root lists").is_empty());
    assert_eq!(
        live_label(&volume),
        (slot, image),
        "the appended label round-trips"
    );
}

#[test]
fn set_label_carries_the_maximum_of_eleven_characters() {
    let mut volume = formatted();
    let name = "ELEVENCHARS"; // eleven ASCII characters
    volume
        .set_label(Some(name))
        .expect("the maximum length lands");

    let (slot, image) = live_label(&volume);
    assert!(slot >= 2, "the label sits behind the system entries");
    assert_eq!(image[0], format::ENTRY_VOLUME_LABEL);
    assert_eq!(
        usize::from(image[1]),
        name.encode_utf16().count(),
        "every unit counted"
    );
    assert_eq!(label_text(&image), name, "all eleven round-trip exactly");
}

#[test]
fn set_label_refusals_move_not_a_byte() {
    let mut volume = labelled();
    let before = volume.volume.bytes().to_vec();

    // Twelve characters: over the limit, refusing with the exact
    // text the formatter's own label validation carries.
    let error = volume
        .set_label(Some("TWELVE_CHARS"))
        .expect_err("twelve characters refuse");
    let text = error.to_string();
    assert!(
        text.contains("an exFAT label holds 11 characters, this one needs 12"),
        "the refusal quotes the limit: {text}"
    );
    assert!(text.is_ascii(), "refusals stay ascii: {text}");

    // A forbidden character refuses with the character named.
    let error = volume
        .set_label(Some("BAD:NAME"))
        .expect_err("the colon refuses");
    let text = error.to_string();
    assert!(
        text.contains("an exFAT label cannot contain the character U+003A"),
        "the refusal names the character: {text}"
    );
    assert!(text.is_ascii(), "refusals stay ascii: {text}");

    assert_eq!(volume.volume.bytes(), &before[..], "neither refusal wrote");
    assert_eq!(
        label_text(&live_label(&volume).1),
        "FURUS",
        "the live label is untouched"
    );
}

#[test]
fn clearing_a_label_that_was_never_there_writes_nothing() {
    let mut volume = formatted();
    let before = volume.volume.bytes().to_vec();

    // `None` with no live label anywhere: Ok, and not one byte moves.
    volume.set_label(None).expect("the clear is a no-op");
    assert_eq!(volume.volume.bytes(), &before[..], "not one byte moved");
    // An empty string clears, matching format(): also a no-op here.
    volume
        .set_label(Some(""))
        .expect("an empty label clears like None");
    assert_eq!(
        volume.volume.bytes(),
        &before[..],
        "the empty label moved nothing either"
    );
}

#[test]
fn a_cleared_label_is_set_again_behind_the_marker() {
    let mut volume = labelled();
    volume.set_label(None).expect("the clear lands");
    assert_eq!(
        root_slot(&volume, 0)[0],
        format::ENTRY_VOLUME_LABEL & !dirent::ENTRY_IN_USE,
        "the old slot is left deleted"
    );

    volume
        .set_label(Some("THIRD"))
        .expect("the second set lands");
    let (slot, image) = live_label(&volume);
    assert_eq!(
        slot, 3,
        "the fresh label appended at the marker, not into the deleted slot 0"
    );
    assert_eq!(label_text(&image), "THIRD");
    let marker = root_slot(&volume, slot + 1);
    assert!(
        marker.iter().all(|byte| *byte == 0),
        "the marker moved one slot back"
    );

    // Open still succeeds — the deleted slot never blocks the walk.
    let volume = reopened(&mut volume);
    assert_eq!(
        live_label(&volume),
        (slot, image),
        "the relabelled volume reopens"
    );
    assert!(volume.list_dir("/").expect("the root lists").is_empty());
}

/// A foreign root whose end-of-directory marker is its very last
/// slot refuses a fresh label with
/// [`fresh_label_slot`]'s exact "leaving no slot behind the marker"
/// text. The shape cannot come from a crate-created image (this
/// crate's format and growth always leave zeros behind the marker),
/// so the test builds the foreign copy byte by byte: the old marker
/// slot and every slot after it carry the deleted-label shape the
/// crate itself writes on a clear (lead 0x03, zeros), leaving the
/// root's last slot as the only 0x00 lead. The refusal must move
/// not one further byte.
#[test]
fn set_label_refuses_a_foreign_root_without_a_slot_behind_the_marker() {
    let mut volume = formatted();
    let root = volume.root_level().expect("the root reads");
    let listing = dirent::parse_dir_listing(&root.content.bytes).expect("the listing parses");
    let total = root.content.bytes.len() / format::ENTRY_BYTES;
    // One deleted-label slot: lead 0x03 over zeros — the shape
    // clear_label leaves behind (the crate's own deleted form).
    let mut filler = [0_u8; format::ENTRY_BYTES];
    filler[0] = format::ENTRY_VOLUME_LABEL & !dirent::ENTRY_IN_USE;
    for slot in listing.terminator_slot..total.saturating_sub(1) {
        let at = root
            .content
            .slot_address(volume.geometry(), slot)
            .expect("the slot has an address");
        volume
            .volume
            .write_all_at(at, &filler)
            .expect("the deleted-lead slot fills");
    }

    let mut volume = reopened(&mut volume);
    let untouched = volume.volume.bytes().to_vec();
    let root = volume.root_level().expect("the root reads");
    let listing = dirent::parse_dir_listing(&root.content.bytes).expect("the listing parses");
    assert_eq!(
        listing.terminator_slot,
        listing.total_slots - 1,
        "the copy's marker sits on the root's last slot"
    );
    let expected = format!(
        "the root directory ends at slot {} of {} slots, leaving no slot behind \
         the marker for a fresh label",
        listing.terminator_slot, listing.total_slots
    );
    let error = volume
        .set_label(Some("FRESH"))
        .expect_err("a marker with no slot behind it refuses a fresh label");
    let text = error.to_string();
    assert!(
        text.contains(&expected),
        "the refusal quotes fresh_label_slot's exact text: {text}"
    );
    assert!(text.is_ascii(), "refusals stay ascii: {text}");
    assert_eq!(
        volume.volume.bytes(),
        &untouched[..],
        "the refusal moved not a byte"
    );
}

/// The sibling refusal, the non-zero slot behind the marker: a
/// foreign root whose slot behind the first end-of-directory marker
/// is filled with 0xFF bytes (never a shape this crate writes)
/// refuses a fresh label with
/// [`fresh_label_slot`]'s exact "the slot behind the marker is not
/// zeroed" text, and again refuses without moving a further byte.
#[test]
fn set_label_refuses_a_foreign_root_with_a_used_slot_behind_the_marker() {
    let mut volume = formatted();
    let root = volume.root_level().expect("the root reads");
    let listing = dirent::parse_dir_listing(&root.content.bytes).expect("the listing parses");
    let behind = root
        .content
        .slot_address(volume.geometry(), listing.terminator_slot + 1)
        .expect("the slot behind the marker has an address");
    let poison = [0xFF_u8; format::ENTRY_BYTES];
    volume
        .volume
        .write_all_at(behind, &poison)
        .expect("the poison lands behind the marker");

    let mut volume = reopened(&mut volume);
    let untouched = volume.volume.bytes().to_vec();
    let root = volume.root_level().expect("the root reads");
    let listing = dirent::parse_dir_listing(&root.content.bytes).expect("the listing parses");
    assert_eq!(
        listing.terminator_slot, 2,
        "the marker kept its slot behind the bitmap and up-case entries"
    );
    let expected = format!(
        "the root directory ends at slot {} of {} slots, but the slot behind \
         the marker is not zeroed, so a fresh label would erase the end-of-directory \
         marker",
        listing.terminator_slot, listing.total_slots
    );
    let error = volume
        .set_label(Some("FRESH"))
        .expect_err("a used slot behind the marker refuses a fresh label");
    let text = error.to_string();
    assert!(
        text.contains(&expected),
        "the refusal quotes fresh_label_slot's exact text: {text}"
    );
    assert!(text.is_ascii(), "refusals stay ascii: {text}");
    assert_eq!(
        volume.volume.bytes(),
        &untouched[..],
        "the refusal moved not a byte"
    );
}
