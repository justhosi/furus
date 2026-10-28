//! Streaming digests for images, files and plan confirms (S03).
//!
//! The [`Algo`] selection mirrors Rufus's checksum dialog: MD5, SHA-1,
//! SHA-256 and SHA-512, streamed over a 1 MiB buffer so a multi-gigabyte
//! ISO never resides in memory. [`hash_reader`] digests anything
//! [`Read`]-able; [`hash_file`] is the regular-file convenience wrapper
//! that defaults to SHA-256 (the image/plans default) and keeps the
//! offending path in [`CoreError::Io`] errors.
//!
//! Dependencies are the RustCrypto crates `md-5`, `sha1` and `sha2` only.
//! The shared [`Digest`] bound comes from `sha2::Digest`, which `sha2`
//! re-exports from the `digest` crate all four hashers implement.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use md5::Md5;
use sha1::Sha1;
use sha2::Digest;
use sha2::Sha256;
use sha2::Sha512;

use crate::error;
use crate::error::CoreError;
use crate::error::Result;

/// Digest algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algo {
    /// MD5 (128-bit). For compatibility listings only, like Rufus.
    Md5,
    /// SHA-1 (160-bit).
    Sha1,
    /// SHA-256, the default for plans and verification.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl Algo {
    /// Lowercase canonical name, as accepted by [`Algo::from_str`] and
    /// echoed in the `checksum --json` output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

impl FromStr for Algo {
    type Err = CoreError;

    /// Accepts `md5`, `sha1`, `sha256`, `sha512` ASCII case-insensitively;
    /// anything else is [`CoreError::InvalidInput`] naming the input.
    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        for (name, algo) in [
            ("md5", Self::Md5),
            ("sha1", Self::Sha1),
            ("sha256", Self::Sha256),
            ("sha512", Self::Sha512),
        ] {
            if name.eq_ignore_ascii_case(text) {
                return Ok(algo);
            }
        }
        Err(CoreError::invalid(format!(
            "unknown hash algorithm '{text}' (expected md5, sha1, sha256 or sha512)"
        )))
    }
}

/// Lowercase hex; small enough that no `hex` crate dependency is justified.
fn hex(buf: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(buf.len() * 2);
    for &b in buf {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Stream-size of every [`hash_reader`] and [`hash_file_with`] chunk.
const CHUNK: usize = 1024 * 1024;

/// Digest a [`Read`]-able input with `algo`, returning lowercase hex.
///
/// Input errors are reported as [`CoreError::Io`] with the placeholder
/// path `"<reader>"` — a reader carries no path of its own; callers that
/// know one (e.g. [`hash_file_with`]) either map it themselves before
/// handing the file over, like the CLI does after checking the path, or
/// rewrite the error path at their own layer.
fn digest<D: Digest, R: Read>(algo_label: &'static str, mut reader: R) -> Result<String> {
    let mut hasher = D::new();
    let mut buf = vec![0u8; CHUNK];
    let label = format!("<{algo_label} reader>");
    loop {
        let n = reader.read(&mut buf).map_err(|source| CoreError::Io {
            path: label.clone(),
            source,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Hash `reader` with `algo`; see the module header for error semantics.
pub fn hash_reader<R: Read>(algo: Algo, reader: R) -> Result<String> {
    match algo {
        Algo::Md5 => digest::<Md5, _>(algo.as_str(), reader),
        Algo::Sha1 => digest::<Sha1, _>(algo.as_str(), reader),
        Algo::Sha256 => digest::<Sha256, _>(algo.as_str(), reader),
        Algo::Sha512 => digest::<Sha512, _>(algo.as_str(), reader),
    }
}

/// Hash the file at `path` with `algo`, keeping `path` in I/O errors.
pub fn hash_file_with(algo: Algo, path: &Path) -> Result<String> {
    let file = File::open(path).map_err(|source| error::CoreError::io(path, source))?;
    hash_reader(algo, file)
}

/// Hash the file at `path` with the default algorithm (SHA-256).
///
/// Explicit-algorithm callers use [`hash_file_with`] instead.
pub fn hash_file(path: &Path) -> Result<String> {
    hash_file_with(Algo::Sha256, path)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::io::Read;

    use super::*;

    /// RFC 1321 (MD5), RFC 3174 (SHA-1), RFC 6234 / FIPS 180-4 vectors.
    const VECTORS: &[(Algo, &str, &str)] = &[
        (Algo::Md5, "d41d8cd98f00b204e9800998ecf8427e", ""),
        (Algo::Md5, "900150983cd24fb0d6963f7d28e17f72", "abc"),
        (Algo::Sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", ""),
        (
            Algo::Sha1,
            "a9993e364706816aba3e25717850c26c9cd0d89d",
            "abc",
        ),
        (
            Algo::Sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "",
        ),
        (
            Algo::Sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "abc",
        ),
        (
            Algo::Sha512,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            "",
        ),
        (
            Algo::Sha512,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "abc",
        ),
    ];

    #[test]
    fn stream_vectors_match_rfc_test_cases() {
        for (algo, want, input) in VECTORS {
            let got = hash_reader(*algo, Cursor::new(input.as_bytes())).expect("hash");
            assert!(got.eq_ignore_ascii_case(want), "{algo:?} {input:?}: {got}");
        }
    }

    #[test]
    fn parse_is_case_insensitive_and_strict() {
        for (name, algo) in [
            ("md5", Algo::Md5),
            ("sha1", Algo::Sha1),
            ("sha256", Algo::Sha256),
            ("sha512", Algo::Sha512),
        ] {
            let lower: Algo = name.parse().expect(name);
            assert_eq!(lower, algo);
            let upper: Algo = name.to_ascii_uppercase().parse().expect(name);
            assert_eq!(upper, algo);
        }
        let err = "sha224".parse::<Algo>().expect_err("unsupported");
        let text = err.to_string();
        assert!(text.contains("sha224"), "{text}");
        assert!(text.contains("expected md5"), "{text}");
        assert!("".parse::<Algo>().is_err());
    }

    #[test]
    fn as_str_is_the_canonical_name() {
        assert_eq!(Algo::Md5.as_str(), "md5");
        assert_eq!(Algo::Sha1.as_str(), "sha1");
        assert_eq!(Algo::Sha256.as_str(), "sha256");
        assert_eq!(Algo::Sha512.as_str(), "sha512");
    }

    #[test]
    fn hash_file_hashes_and_names_missing_paths() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("abc.bin");
        std::fs::write(&path, b"abc").expect("seed file");
        for (name, want) in [
            ("md5", "900150983cd24fb0d6963f7d28e17f72"),
            (
                "sha256",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
        ] {
            let algo: Algo = name.parse().expect("vector algorithm");
            let got = hash_file_with(algo, &path).expect("file exists");
            assert!(got.eq_ignore_ascii_case(want), "{algo:?}: {got}");
        }
        // Default is SHA-256, the plan/image digest.
        assert_eq!(
            hash_file(&path).expect("sha256 by default"),
            hash_file_with(Algo::Sha256, &path).expect("same input")
        );

        // A missing path surfaces as Io naming the path (not "<reader>").
        let missing = dir.path().join("gone.bin");
        let err = hash_file(&missing).expect_err("file absent").to_string();
        assert!(err.contains("gone.bin"), "{err}");
    }

    #[test]
    fn one_mib_plus_hash_is_stable_across_read_patterns() {
        // 1 MiB + 17 bytes runs past the internal chunk boundary, hashed
        // through three independent read patterns: full-chunk reads from a
        // File (hash_file_with), one large Cursor read, and 1-byte reads.
        let mut data = vec![0u8; CHUNK + 17];
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = (i % 253) as u8; // deterministic pattern
        }
        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("big.bin");
        std::fs::write(&path, &data).expect("seed file");

        let digest_file = hash_file_with(Algo::Sha256, &path).expect("file digest");
        let digest_reader = hash_reader(Algo::Sha256, Cursor::new(&data)).expect("reader digest");
        assert_eq!(digest_file, digest_reader);

        // Confirm the chunking with a byte-at-a-time reader behind the same
        // public API (external-tool comparison is the S27 harness's job).
        let mut one_byte = OneByteReader {
            data: &data,
            pos: 0,
        };
        let digest_bytes = hash_reader(Algo::Sha256, &mut one_byte).expect("byte digest");
        assert_eq!(digest_file, digest_bytes);
    }

    /// Test-only reader that hands out exactly one byte per `read` call so
    /// the chunk loop cannot assume anything about read sizes.
    struct OneByteReader<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl Read for OneByteReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.is_empty() || self.pos >= self.data.len() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    #[test]
    fn empty_input_matches_rfc_and_regular_files() {
        // Empty stream == empty file == RFC empty-string vector.
        let stream = hash_reader(Algo::Sha256, Cursor::new(Vec::<u8>::new())).expect("empty");
        assert!(stream.starts_with("e3b0c44298fc1c14"));

        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, b"").expect("seed empty");
        assert_eq!(hash_file(&path).expect("empty file"), stream);
    }
}
