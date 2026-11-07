//! Generic `regf` hive editor backing the BCD and To Go writers (S21, slice 7 of 12).
//!
//! Extracted verbatim from `windows::bcd` with the same behaviour: parse and
//! structural validation, free-cell first-fit allocation with neighbour merging,
//! in-place growth, whole-bin appends, key lookup, value read/write, key and value
//! creation, and header-checksum recompute. The only deliberate change from the
//! `bcd` original is that parsing no longer pins the root key name: the BCD
//! template roots at `System` while a real `SYSTEM` hive roots at `ROOT`, so the
//! name check lives in `windows::bcd` where the template shape is known.
//!
//! Layout notes live with the constants below; the editor never allocates outside
//! its own free cells except by appending whole 4 KiB `hbin` pages.

use crate::error::CoreError;
use crate::error::Result;

/// Magic at header offset 0.
pub(crate) const HDR_MAGIC: &[u8; 4] = b"regf";
/// Header offset of the root cell offset (`u32`).
pub(crate) const HDR_ROOT: usize = 0x24;
/// Header offset of the total hive-bin length (`u32`).
pub(crate) const HDR_BIN_LENGTH: usize = 0x28;
/// Header offset of the checksum (`u32`).
pub(crate) const HDR_CHECKSUM: usize = 0x1FC;
/// Minimum readable header: the checksum word must be present.
pub(crate) const HDR_MIN_LEN: usize = 0x200;
/// File offset of the first hive bin.
pub(crate) const BIN_BASE: usize = 4096;
/// Hive bin page size; appended bins use the same size.
pub(crate) const BIN_SIZE: usize = 0x1000;
/// Hive bin header length; cells start here.
pub(crate) const HBIN_HEAD: usize = 0x20;
/// Usable bytes of a fresh appended bin (one free cell).
pub(crate) const HBIN_USABLE: usize = BIN_SIZE - HBIN_HEAD;
/// Cell offsets are relative to this file offset.
pub(crate) const CELL_BASE: usize = 4096;
/// Minimum cell size (header plus a token body).
pub(crate) const MIN_CELL: usize = 8;
/// Cell size granularity.
pub(crate) const CELL_ROUND: usize = 8;
/// Offset meaning "no cell".
pub(crate) const NONE: u32 = 0xFFFF_FFFF;
/// `nk` name-length field offset (tag-relative).
pub(crate) const NK_NAMELEN: usize = 0x48;
/// `nk` name field offset (tag-relative).
pub(crate) const NK_NAME: usize = 0x4C;
/// `nk` fixed body length (tag through name-length bytes).
pub(crate) const NK_FIXED: usize = 0x4C;
/// `nk` flags value for a latin-1 (compressed) name.
pub(crate) const NK_COMPRESSED: u16 = 0x20;
/// `vk` fixed header length (tag through flags).
pub(crate) const VK_FIXED: usize = 0x14;
/// `vk` flags value for a latin-1 value name.
pub(crate) const VK_LATIN1: u16 = 0x0001;
/// `vk` data-size bit for inline (resident) data.
pub(crate) const INLINE_FLAG: u32 = 0x8000_0000;
/// Subkey-list count field offset (tag-relative).
pub(crate) const LIST_COUNT: usize = 0x02;
/// Subkey-list entries offset (tag-relative).
pub(crate) const LIST_ENTRIES: usize = 0x04;
/// Value types the builder reads and writes.
pub(crate) const REG_SZ: u32 = 1;
pub(crate) const REG_BINARY: u32 = 3;
pub(crate) const REG_MULTI_SZ: u32 = 7;
/// Value type for `REG_DWORD` inline integers (for example `Select\Current` and `SanPolicy`).
pub(crate) const REG_DWORD: u32 = 4;

/// Write `bytes` at `at` inside a fixed buffer, without indexing.
///
/// The device layouts use only compile-time offsets inside `[u8; 88]`,
/// so a short write is a programming error: it is caught by
/// `debug_assert` in tests and the unit tests pin every byte anyway.
pub(crate) fn imprint<const N: usize>(buf: &mut [u8; N], at: usize, bytes: &[u8]) {
    debug_assert!(
        at.checked_add(bytes.len()).is_some_and(|end| end <= N),
        "device field at {at:#x} does not fit"
    );
    for (slot, byte) in buf.iter_mut().skip(at).take(bytes.len()).zip(bytes.iter()) {
        *slot = *byte;
    }
}

/// Encode `text` as UTF-16LE with a single NUL terminator (`REG_SZ` body).
pub(crate) fn utf16_nul(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len().saturating_mul(2).saturating_add(2));
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// Encode `items` as UTF-16LE NUL-separated with a final extra NUL
/// (`REG_MULTI_SZ` body).
pub(crate) fn utf16_multisz(items: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(&utf16_nul(item));
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// Decode a `REG_SZ` body, stripping the single trailing NUL.
pub(crate) fn decode_sz(data: &[u8]) -> Result<String> {
    Ok(decode_utf16(data, "REG_SZ")?
        .strip_suffix('\0')
        .unwrap_or_default()
        .to_string())
}

/// Decode a `REG_MULTI_SZ` body into its strings.
#[cfg(test)]
pub(crate) fn decode_multisz(data: &[u8]) -> Result<Vec<String>> {
    let text = decode_utf16(data, "REG_MULTI_SZ")?;
    let mut parts: Vec<String> = text.split('\0').map(str::to_string).collect();
    while parts.last().is_some_and(String::is_empty) {
        parts.pop();
    }
    Ok(parts)
}

/// Decode whole-UTF-16LE-units data.
pub(crate) fn decode_utf16(data: &[u8], what: &str) -> Result<String> {
    if !data.len().is_multiple_of(2) {
        return Err(CoreError::invalid(format!(
            "bcd {what} value is {} bytes, not whole UTF-16 units",
            data.len()
        )));
    }
    let mut units = Vec::with_capacity(data.len().saturating_add(1) / 2);
    for pair in data.as_chunks::<2>().0 {
        units.push(u16::from_le_bytes(*pair));
    }
    String::from_utf16(&units)
        .map_err(|_| CoreError::invalid(format!("bcd {what} value is not valid UTF-16")))
}

/// Format an element id as 8 uppercase hex digits (the `Elements`
/// subkey name shape the template uses).
pub(crate) fn element_name(id: u32) -> [u8; 8] {
    let mut name = [b'0'; 8];
    let mut rest = id;
    for slot in name.iter_mut().rev() {
        let nibble = (rest & 0xF) as u8;
        *slot = if nibble < 10 {
            b'0' + nibble
        } else {
            b'A' + (nibble - 10)
        };
        rest >>= 4;
    }
    name
}

/// The subkey-list hash convention this file family uses: the first 4
/// name bytes as little-endian `u32` (all 101 template entries
/// verify). Names here are always at least 4 bytes; shorter names
/// zero-pad.
pub(crate) fn lf_hash(name: &[u8]) -> u32 {
    let mut first = [0u8; 4];
    for (slot, byte) in first.iter_mut().zip(name.iter()) {
        *slot = *byte;
    }
    u32::from_le_bytes(first)
}

/// Compare a stored key or value name against an ASCII want: latin-1
/// compares byte-for-byte, UTF-16LE compares against the widened want.
pub(crate) fn name_matches(stored: &[u8], latin1: bool, want: &[u8]) -> bool {
    if latin1 {
        return stored == want;
    }
    if stored.len() != want.len().saturating_mul(2) {
        return false;
    }
    stored
        .as_chunks::<2>()
        .0
        .iter()
        .zip(want.iter())
        .all(|(pair, byte)| matches!(pair, [lo, 0] if lo == byte))
}

/// A parsed hive: the owned bytes plus the validated root cell offset.
pub(crate) struct Hive {
    pub(crate) buf: Vec<u8>,
    pub(crate) root: usize,
}

impl Hive {
    /// File offset of `cell` (cells are relative to 4096).
    pub(crate) fn cell_file(cell: usize, what: &str) -> Result<usize> {
        cell.checked_add(CELL_BASE).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd cell offset {cell:#x} overflows reading {what}"
            ))
        })
    }

    /// Copy `N` bytes at `at`, refusing short reads with context.
    pub(crate) fn read_at<const N: usize>(&self, at: usize, what: &str) -> Result<[u8; N]> {
        let end = at.checked_add(N).ok_or_else(|| {
            CoreError::invalid(format!(
                "registry hive ends before {what} at offset {at:#x}"
            ))
        })?;
        let slice = self.buf.get(at..end).ok_or_else(|| {
            CoreError::invalid(format!(
                "registry hive ends before {what} at offset {at:#x}"
            ))
        })?;
        let mut out = [0u8; N];
        for (slot, byte) in out.iter_mut().zip(slice.iter()) {
            *slot = *byte;
        }
        Ok(out)
    }

    pub(crate) fn read_u16(&self, at: usize, what: &str) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_at(at, what)?))
    }

    pub(crate) fn read_u32(&self, at: usize, what: &str) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_at(at, what)?))
    }

    pub(crate) fn read_i32(&self, at: usize, what: &str) -> Result<i32> {
        Ok(i32::from_le_bytes(self.read_at(at, what)?))
    }

    /// Write `bytes` at `at`, refusing short writes with context.
    pub(crate) fn store_at(&mut self, at: usize, bytes: &[u8], what: &str) -> Result<()> {
        let end = at.checked_add(bytes.len()).ok_or_else(|| {
            CoreError::invalid(format!("bcd cell offset {at:#x} overflows writing {what}"))
        })?;
        if end > self.buf.len() {
            return Err(CoreError::invalid(format!(
                "registry hive ends at {:#x} before {what} at offset {at:#x}",
                self.buf.len()
            )));
        }
        let Some(window) = self.buf.get_mut(at..end) else {
            return Err(CoreError::invalid(format!(
                "bcd write window vanished writing {what} at offset {at:#x}"
            )));
        };
        window.copy_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn store_u16(&mut self, at: usize, value: u16, what: &str) -> Result<()> {
        self.store_at(at, &value.to_le_bytes(), what)
    }

    pub(crate) fn store_u32(&mut self, at: usize, value: u32, what: &str) -> Result<()> {
        self.store_at(at, &value.to_le_bytes(), what)
    }

    /// The XOR of the 127 `u32` words at `0x00..=0x1FB`, or `None`
    /// when the header is short.
    pub(crate) fn header_checksum(buf: &[u8]) -> Option<u32> {
        let head = buf.get(..HDR_CHECKSUM)?;
        let mut xor = 0u32;
        for chunk in head.as_chunks::<4>().0 {
            xor ^= u32::from_le_bytes(*chunk);
        }
        Some(xor)
    }

    /// Root cell offset recorded at parse time.
    pub(crate) fn root(&self) -> usize {
        self.root
    }

    /// Parse and structurally validate a template hive.
    pub(crate) fn parse(template: &[u8]) -> Result<Self> {
        if template.len() < HDR_MIN_LEN {
            return Err(CoreError::invalid(format!(
                "registry hive is {} bytes, smaller than the 512-byte registry header",
                template.len()
            )));
        }
        let magic: [u8; 4] = template
            .get(..4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| CoreError::invalid("registry hive ends before the magic".to_string()))?;
        if &magic != HDR_MAGIC {
            return Err(CoreError::invalid(
                "registry hive is not a registry hive: bad magic".to_string(),
            ));
        }
        let bin_len = u32::from_le_bytes(
            template
                .get(HDR_BIN_LENGTH..HDR_BIN_LENGTH + 4)
                .and_then(|slice| slice.try_into().ok())
                .ok_or_else(|| {
                    CoreError::invalid("registry hive ends before the hive-bin length".to_string())
                })?,
        ) as usize;
        if bin_len < BIN_SIZE {
            return Err(CoreError::invalid(format!(
                "registry hive declares {bin_len} bytes of bins, smaller than one 4096-byte hive bin"
            )));
        }
        if !bin_len.is_multiple_of(BIN_SIZE) {
            return Err(CoreError::invalid(format!(
                "registry hive declares {bin_len} bytes of bins, not a multiple of 4096"
            )));
        }
        let declared_end = BIN_BASE.checked_add(bin_len).ok_or_else(|| {
            CoreError::invalid(format!(
                "registry hive declares {bin_len} bytes of bins that overflow"
            ))
        })?;
        if declared_end > template.len() {
            let short = declared_end.saturating_sub(template.len());
            return Err(CoreError::invalid(format!(
                "registry hive declares {bin_len} bytes of bins ending at {declared_end:#x} but the buffer is {} bytes (short by {short} bytes)",
                template.len()
            )));
        }
        let mut hive = Self {
            buf: template[..declared_end].to_vec(),
            root: 0,
        };
        let root = hive.read_u32(HDR_ROOT, "root cell offset")? as usize;
        let root_file = Self::cell_file(root, "root cell")?;
        let root_end = root_file.checked_add(6).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd root cell offset {root:#x} overflows the template"
            ))
        })?;
        let root_tag = hive.buf.get(root_file..root_end).ok_or_else(|| {
            CoreError::invalid(format!(
                "registry hive of {} bytes has no root cell at offset {root:#x}",
                hive.buf.len()
            ))
        })?;
        if root_tag.get(4..6) != Some(b"nk".as_slice()) {
            return Err(CoreError::invalid(format!(
                "registry hive root at offset {root:#x} is not a key"
            )));
        }
        hive.root = root;
        hive.check_bins()?;
        let stored = hive.read_u32(HDR_CHECKSUM, "header checksum")?;
        let computed = Self::header_checksum(&hive.buf).ok_or_else(|| {
            CoreError::invalid("registry hive ends before the header checksum".to_string())
        })?;
        if stored != computed {
            return Err(CoreError::invalid(format!(
                "registry hive checksum mismatch: stored {stored:#x}, computed {computed:#x}"
            )));
        }
        Ok(hive)
    }

    /// Validate the hive-bin tiling and every cell size.
    pub(crate) fn check_bins(&self) -> Result<()> {
        let len = self.buf.len();
        if len < BIN_BASE + HBIN_HEAD {
            return Err(CoreError::invalid(format!(
                "registry hive is {len} bytes, smaller than one 4128-byte hive bin"
            )));
        }
        if !len.is_multiple_of(BIN_SIZE) {
            let short = BIN_SIZE.saturating_sub(len % BIN_SIZE);
            return Err(CoreError::invalid(format!(
                "registry hive length {len} is not a whole number of 4 KiB hive bins (short by {short} bytes)"
            )));
        }
        let mut bin = BIN_BASE;
        while bin < len {
            let magic: [u8; 4] = self.read_at(bin, "hive bin magic")?;
            if &magic != b"hbin" {
                return Err(CoreError::invalid(format!(
                    "registry hive hive bin at offset {bin:#x} has bad magic"
                )));
            }
            let size = self.read_i32(bin + 8, "hive bin size")?;
            if size < BIN_SIZE as i32 || size % BIN_SIZE as i32 != 0 {
                return Err(CoreError::invalid(format!(
                    "registry hive hive bin at offset {bin:#x} has size {size}, expected a positive multiple of 4096"
                )));
            }
            let size = size as usize;
            let bin_end = bin.checked_add(size).ok_or_else(|| {
                CoreError::invalid(format!(
                    "registry hive hive bin at offset {bin:#x} overflows the template"
                ))
            })?;
            if bin_end > len {
                let short = bin_end.saturating_sub(len);
                return Err(CoreError::invalid(format!(
                    "registry hive hive bin at offset {bin:#x} needs {bin_end:#x} bytes but the template ends at {len:#x} (short by {short} bytes)"
                )));
            }
            let mut cur = bin.checked_add(HBIN_HEAD).ok_or_else(|| {
                CoreError::invalid(format!(
                    "registry hive hive bin at offset {bin:#x} overflows the template"
                ))
            })?;
            while cur < bin_end {
                let raw = self.read_i32(cur, "cell size")?;
                if raw == 0 {
                    return Err(CoreError::invalid(format!(
                        "registry hive has a zero-size cell at offset {cur:#x}"
                    )));
                }
                let cap = raw.unsigned_abs() as usize;
                if cap < MIN_CELL || !cap.is_multiple_of(CELL_ROUND) {
                    return Err(CoreError::invalid(format!(
                        "registry hive has a corrupt cell size {raw} at offset {cur:#x}"
                    )));
                }
                cur = cur.checked_add(cap).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "registry hive cell at offset {cur:#x} overflows the template"
                    ))
                })?;
                if cur > bin_end {
                    let short = cur.saturating_sub(bin_end);
                    return Err(CoreError::invalid(format!(
                        "registry hive cell at offset {cur:#x} overruns its hive bin ending at {bin_end:#x} (short by {short} bytes)"
                    )));
                }
            }
            if cur != bin_end {
                return Err(CoreError::invalid(format!(
                    "registry hive cells do not tile the hive bin ending at {bin_end:#x}"
                )));
            }
            bin = bin_end;
        }
        Ok(())
    }

    /// Tag bytes of `cell` (`nk`, `vk`, `lf`, ...).
    pub(crate) fn cell_tag(&self, cell: usize) -> Result<[u8; 2]> {
        let file = Self::cell_file(cell, "cell tag")?;
        let at = file.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd cell offset {cell:#x} overflows reading its tag"
            ))
        })?;
        self.read_at(at, "cell tag")
    }

    /// Body capacity of the cell at file offset `file` (signed size
    /// already read): total minus the 4-byte header.
    pub(crate) fn capacity(raw_size: i32) -> usize {
        (raw_size.unsigned_abs() as usize).saturating_sub(4)
    }

    /// Read a `u32` `nk` field at tag-relative `field`.
    pub(crate) fn nk_u32(&self, cell: usize, field: usize, what: &str) -> Result<u32> {
        let file = Self::cell_file(cell, what)?;
        let body = file.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd cell offset {cell:#x} overflows reading {what}"
            ))
        })?;
        let at = body.checked_add(field).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd cell offset {cell:#x} overflows reading {what}"
            ))
        })?;
        self.read_u32(at, what)
    }

    /// Read the stored name bytes of an `nk` key.
    pub(crate) fn nk_name(&self, cell: usize) -> Result<(Vec<u8>, bool)> {
        let file = Self::cell_file(cell, "key name")?;
        let body = file.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd cell offset {cell:#x} overflows reading key flags"
            ))
        })?;
        let flags = self.read_u16(
            body.checked_add(0x02).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd cell offset {cell:#x} overflows reading key flags"
                ))
            })?,
            "key flags",
        )?;
        let len = self.read_u16(
            body.checked_add(NK_NAMELEN).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd cell offset {cell:#x} overflows reading key name length"
                ))
            })?,
            "key name length",
        )? as usize;
        let at = body.checked_add(NK_NAME).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd cell offset {cell:#x} overflows reading key name"
            ))
        })?;
        let end = at.checked_add(len).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd key at offset {cell:#x} has a name length {len} that overflows"
            ))
        })?;
        let name = self
            .buf
            .get(at..end)
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "registry hive ends before the name of the key at offset {cell:#x}"
                ))
            })?
            .to_vec();
        Ok((name, flags & NK_COMPRESSED != 0))
    }

    /// Read a `u32` `vk` field at tag-relative `field`.
    pub(crate) fn vk_u32(&self, cell: usize, field: usize, what: &str) -> Result<u32> {
        let file = Self::cell_file(cell, what)?;
        let body = file.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd cell offset {cell:#x} overflows reading {what}"
            ))
        })?;
        let at = body.checked_add(field).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd cell offset {cell:#x} overflows reading {what}"
            ))
        })?;
        self.read_u32(at, what)
    }

    /// First subkey of `parent`, or `None` when it has none.
    pub(crate) fn first_child(&self, parent: usize) -> Result<Option<usize>> {
        let nsub = self.nk_u32(parent, 0x14, "subkey count")?;
        if nsub == 0 {
            return Ok(None);
        }
        let list = self.nk_u32(parent, 0x1C, "subkey list")?;
        if list == NONE {
            return Err(CoreError::invalid(format!(
                "bcd key at offset {parent:#x} counts {nsub} subkeys but has no subkey list"
            )));
        }
        let (count, entry_size, _, _) = self.list_head(list as usize)?;
        if count == 0 {
            return Ok(None);
        }
        let _ = entry_size;
        self.list_child(list as usize, 0)
    }

    /// Read a subkey-list head: (count, entry size, entries offset,
    /// has-hash). Validates the tag, the count against the parent key,
    /// and the cell capacity.
    pub(crate) fn list_head(&self, list: usize) -> Result<(u32, usize, usize, bool)> {
        let tag = self.cell_tag(list)?;
        let (entry_size, hashed) = match &tag {
            [b'l', b'f'] | [b'l', b'h'] => (8usize, true),
            [b'l', b'i'] | [b'r', b'i'] => (4usize, false),
            _ => {
                return Err(CoreError::invalid(format!(
                    "bcd subkey list at offset {list:#x} has a bad tag"
                )));
            }
        };
        let file = Self::cell_file(list, "subkey list")?;
        let body = file.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd subkey list at offset {list:#x} overflows reading its count"
            ))
        })?;
        let count = self.read_u16(
            body.checked_add(LIST_COUNT).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd subkey list at offset {list:#x} overflows reading its count"
                ))
            })?,
            "subkey list count",
        )? as u32;
        let entries = body.checked_add(LIST_ENTRIES).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd subkey list at offset {list:#x} overflows reading its entries"
            ))
        })?;
        let raw = self.read_i32(file, "subkey list size")?;
        let cap = Self::capacity(raw);
        let need = (count as usize)
            .checked_mul(entry_size)
            .and_then(|n| n.checked_add(LIST_ENTRIES))
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd subkey list at offset {list:#x} counts {count} entries that overflow"
                ))
            })?;
        if need > cap {
            let short = need.saturating_sub(cap);
            return Err(CoreError::invalid(format!(
                "bcd subkey list at offset {list:#x} needs {need} bytes but its cell holds {cap} (short by {short} bytes)"
            )));
        }
        Ok((count, entry_size, entries, hashed))
    }

    /// The child offset of list entry `index`.
    pub(crate) fn list_child(&self, list: usize, index: u32) -> Result<Option<usize>> {
        let (count, entry_size, entries, _) = self.list_head(list)?;
        if index >= count {
            return Ok(None);
        }
        let at = (index as usize)
            .checked_mul(entry_size)
            .and_then(|n| entries.checked_add(n))
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd subkey list at offset {list:#x} entry {index} overflows"
                ))
            })?;
        let child = self.read_u32(at, "subkey list entry")? as usize;
        let tag = self.cell_tag(child).map_err(|_| {
            CoreError::invalid(format!(
                "bcd subkey list at offset {list:#x} points past the template at {child:#x}"
            ))
        })?;
        if &tag != b"nk" {
            return Err(CoreError::invalid(format!(
                "bcd subkey list at offset {list:#x} points at a non-key cell {child:#x}"
            )));
        }
        Ok(Some(child))
    }

    /// Find the subkey `want` under `parent` by name.
    pub(crate) fn find_child(&self, parent: usize, want: &[u8]) -> Result<Option<usize>> {
        let nsub = self.nk_u32(parent, 0x14, "subkey count")?;
        if nsub == 0 {
            return Ok(None);
        }
        let list = self.nk_u32(parent, 0x1C, "subkey list")?;
        if list == NONE {
            return Err(CoreError::invalid(format!(
                "bcd key at offset {parent:#x} counts {nsub} subkeys but has no subkey list"
            )));
        }
        let list = list as usize;
        let (count, _, _, _) = self.list_head(list)?;
        if count != nsub {
            return Err(CoreError::invalid(format!(
                "bcd key at offset {parent:#x} counts {nsub} subkeys but its list holds {count}"
            )));
        }
        for index in 0..count {
            let Some(child) = self.list_child(list, index)? else {
                return Err(CoreError::invalid(format!(
                    "bcd subkey list at offset {list:#x} lost entry {index}"
                )));
            };
            let (name, latin1) = self.nk_name(child)?;
            if name_matches(&name, latin1, want) {
                return Ok(Some(child));
            }
        }
        Ok(None)
    }

    /// The `vk` offsets listed under an `nk` key.
    pub(crate) fn value_list(&self, key: usize) -> Result<Vec<usize>> {
        let nval = self.nk_u32(key, 0x24, "value count")?;
        if nval == 0 {
            return Ok(Vec::new());
        }
        let list = self.nk_u32(key, 0x28, "value list")?;
        if list == NONE {
            return Err(CoreError::invalid(format!(
                "bcd key at offset {key:#x} counts {nval} values but has no value list"
            )));
        }
        let file = Self::cell_file(list as usize, "value list")?;
        let raw = self.read_i32(file, "value list size")?;
        let cap = Self::capacity(raw);
        let need = (nval as usize).checked_mul(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd key at offset {key:#x} counts {nval} values that overflow"
            ))
        })?;
        if need > cap {
            let short = need.saturating_sub(cap);
            return Err(CoreError::invalid(format!(
                "bcd value list at offset {list:#x} needs {need} bytes but its cell holds {cap} (short by {short} bytes)"
            )));
        }
        let mut out = Vec::with_capacity(nval.min(64) as usize);
        for index in 0..nval {
            let at = file
                .checked_add(4)
                .and_then(|base| {
                    (index as usize)
                        .checked_mul(4)
                        .and_then(|n| base.checked_add(n))
                })
                .ok_or_else(|| {
                    CoreError::invalid(format!(
                        "bcd value list at offset {list:#x} entry {index} overflows"
                    ))
                })?;
            let vk = self.read_u32(at, "value list entry")? as usize;
            let tag = self.cell_tag(vk).map_err(|_| {
                CoreError::invalid(format!(
                    "bcd value list at offset {list:#x} points past the template at {vk:#x}"
                ))
            })?;
            if &tag != b"vk" {
                return Err(CoreError::invalid(format!(
                    "bcd value list at offset {list:#x} points at a non-value cell {vk:#x}"
                )));
            }
            out.push(vk);
        }
        Ok(out)
    }

    /// Find the value `want` under `key` by name.
    pub(crate) fn find_value(&self, key: usize, want: &[u8]) -> Result<Option<usize>> {
        for vk in self.value_list(key)? {
            let file = Self::cell_file(vk, "value name")?;
            let body = file.checked_add(4).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd value at offset {vk:#x} overflows reading its name length"
                ))
            })?;
            let len = self.read_u16(
                body.checked_add(0x02).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "bcd value at offset {vk:#x} overflows reading its name length"
                    ))
                })?,
                "value name length",
            )? as usize;
            let flags = self.read_u16(
                body.checked_add(0x10).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "bcd value at offset {vk:#x} overflows reading its flags"
                    ))
                })?,
                "value flags",
            )?;
            let at = body.checked_add(VK_FIXED).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd value at offset {vk:#x} overflows reading its name"
                ))
            })?;
            let end = at.checked_add(len).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd value at offset {vk:#x} has a name length {len} that overflows"
                ))
            })?;
            let name = self.buf.get(at..end).ok_or_else(|| {
                CoreError::invalid(format!(
                    "registry hive ends before the name of the value at offset {vk:#x}"
                ))
            })?;
            if name_matches(name, flags & VK_LATIN1 != 0, want) {
                return Ok(Some(vk));
            }
        }
        Ok(None)
    }

    /// Read a value's (type, data), following the data cell unless the
    /// value is inline.
    pub(crate) fn value_data(&self, vk: usize) -> Result<(u32, Vec<u8>)> {
        let raw_size = self.vk_u32(vk, 0x04, "value data size")?;
        let vtype = self.vk_u32(vk, 0x0C, "value type")?;
        let len = (raw_size & !INLINE_FLAG) as usize;
        if raw_size & INLINE_FLAG != 0 {
            if len > 4 {
                return Err(CoreError::invalid(format!(
                    "bcd inline value at offset {vk:#x} claims {len} bytes"
                )));
            }
            let file = Self::cell_file(vk, "inline value data")?;
            let body = file.checked_add(4).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd value at offset {vk:#x} overflows reading inline data"
                ))
            })?;
            let at = body.checked_add(0x08).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd value at offset {vk:#x} overflows reading inline data"
                ))
            })?;
            let end = at.checked_add(len).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd inline value at offset {vk:#x} has a length {len} that overflows"
                ))
            })?;
            let data = self
                .buf
                .get(at..end)
                .ok_or_else(|| {
                    CoreError::invalid(format!(
                        "registry hive ends before the inline data at offset {vk:#x}"
                    ))
                })?
                .to_vec();
            return Ok((vtype, data));
        }
        let data_cell = self.vk_u32(vk, 0x08, "value data offset")? as usize;
        let file = Self::cell_file(data_cell, "value data")?;
        let raw = self.read_i32(file, "value data cell size")?;
        let cap = Self::capacity(raw);
        if len > cap {
            let short = len.saturating_sub(cap);
            return Err(CoreError::invalid(format!(
                "bcd value at offset {vk:#x} needs {len} data bytes but its cell holds {cap} (short by {short} bytes)"
            )));
        }
        let at = file.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd value data cell at offset {data_cell:#x} overflows"
            ))
        })?;
        let end = at.checked_add(len).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd value at offset {vk:#x} has a data length {len} that overflows"
            ))
        })?;
        let data = self
            .buf
            .get(at..end)
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "registry hive ends before the data of the value at offset {vk:#x}"
                ))
            })?
            .to_vec();
        Ok((vtype, data))
    }

    /// Read one BCD element under an `Elements` key: the (`Element`,
    /// (type, data)) of `Elements\{id}`.
    pub(crate) fn element_value(&self, elements: usize, id: u32) -> Result<Option<(u32, Vec<u8>)>> {
        let name = element_name(id);
        let Some(key) = self.find_child(elements, &name)? else {
            return Ok(None);
        };
        let Some(vk) = self.find_value(key, b"Element")? else {
            return Ok(None);
        };
        Ok(Some(self.value_data(vk)?))
    }

    /// Read one BCD element under `Objects\{object}`.
    #[cfg(test)]
    pub(crate) fn element_data(&self, object: &str, id: u32) -> Result<Option<(u32, Vec<u8>)>> {
        let objects = self.find_child(self.root, b"Objects")?.ok_or_else(|| {
            CoreError::invalid("registry hive has no System\\Objects key".to_string())
        })?;
        let Some(key) = self.find_child(objects, object.as_bytes())? else {
            return Ok(None);
        };
        let Some(elements) = self.find_child(key, b"Elements")? else {
            return Ok(None);
        };
        self.element_value(elements, id)
    }

    /// Round `4 + body` up to the cell granularity, refusing overflow.
    pub(crate) fn cell_total(body_len: usize) -> Result<usize> {
        let total = body_len.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "registry hive has no room for a {body_len}-byte cell body"
            ))
        })?;
        total
            .checked_add(CELL_ROUND - 1)
            .map(|v| v & !(CELL_ROUND - 1))
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "registry hive has no room for a {body_len}-byte cell body"
                ))
            })
    }

    /// Mark the cell at file offset `file` allocated (`size` negative).
    pub(crate) fn mark_allocated(&mut self, file: usize, total: usize) -> Result<()> {
        let size = i32::try_from(total).map_err(|_| {
            CoreError::invalid(format!(
                "registry hive has no room for a {total}-byte cell (largest single cell is 4064 bytes)"
            ))
        })?;
        self.store_at(file, &(-size).to_le_bytes(), "cell size")?;
        self.zero_body(file, total.saturating_sub(4))
    }

    /// Zero `len` bytes starting at absolute offset `at`.
    pub(crate) fn zero_range(&mut self, mut at: usize, mut remaining: usize) -> Result<()> {
        while remaining > 0 {
            let step = remaining.min(4096);
            self.store_at(at, &vec![0u8; step], "zero fill")?;
            at = at.checked_add(step).ok_or_else(|| {
                CoreError::invalid(format!("bcd range at offset {at:#x} overflows zeroing"))
            })?;
            remaining = remaining.saturating_sub(step);
        }
        Ok(())
    }

    /// Zero `len` body bytes after the size header at `file`.
    pub(crate) fn zero_body(&mut self, file: usize, len: usize) -> Result<()> {
        let at = file.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!("bcd cell at offset {file:#x} overflows zeroing"))
        })?;
        self.zero_range(at, len)
    }

    /// Allocate a cell with a `body_len`-byte body: first fit from the
    /// hive's own free cells (splitting a larger one), else an appended
    /// hive bin page. Returns the cell offset.
    pub(crate) fn alloc(&mut self, body_len: usize) -> Result<usize> {
        let total = Self::cell_total(body_len)?;
        if total > HBIN_USABLE {
            let free = self.free_space();
            return Err(CoreError::invalid(format!(
                "registry hive needs {total} bytes but only {free} are free (largest single cell is 4064 bytes)"
            )));
        }
        loop {
            if let Some(cell) = self.take_free(total)? {
                return Ok(cell);
            }
            self.append_hbin()?;
        }
    }

    /// Take the first free cell holding `total` bytes, splitting a
    /// larger one when the remainder stays a valid cell.
    pub(crate) fn take_free(&mut self, total: usize) -> Result<Option<usize>> {
        let len = self.buf.len();
        let mut bin = BIN_BASE;
        while bin < len {
            let size = self.read_i32(bin + 8, "hive bin size")?;
            if size < BIN_SIZE as i32 || size % BIN_SIZE as i32 != 0 {
                return Err(CoreError::invalid(format!(
                    "registry hive hive bin at offset {bin:#x} has size {size}"
                )));
            }
            let bin_end = bin.checked_add(size as usize).ok_or_else(|| {
                CoreError::invalid(format!(
                    "registry hive hive bin at offset {bin:#x} overflows the template"
                ))
            })?;
            let mut cur = bin.checked_add(HBIN_HEAD).ok_or_else(|| {
                CoreError::invalid(format!(
                    "registry hive hive bin at offset {bin:#x} overflows the template"
                ))
            })?;
            while cur < bin_end {
                let raw = self.read_i32(cur, "cell size")?;
                let cap = Self::capacity(raw);
                if raw > 0 && cap + 4 >= total {
                    let have = cap + 4;
                    let rest = have.saturating_sub(total);
                    if rest >= MIN_CELL {
                        self.mark_allocated(cur, total)?;
                        let next = cur.checked_add(total).ok_or_else(|| {
                            CoreError::invalid(format!(
                                "bcd cell at offset {cur:#x} overflows splitting"
                            ))
                        })?;
                        let free_size = i32::try_from(rest).map_err(|_| {
                            CoreError::invalid(format!(
                                "registry hive has no room for a {rest}-byte free cell"
                            ))
                        })?;
                        self.store_at(next, &free_size.to_le_bytes(), "free cell size")?;
                    } else {
                        self.mark_allocated(cur, have)?;
                    }
                    let cell = cur.checked_sub(CELL_BASE).ok_or_else(|| {
                        CoreError::invalid(format!(
                            "bcd cell at file offset {cur:#x} is below the cell base"
                        ))
                    })?;
                    return Ok(Some(cell));
                }
                cur = cur.checked_add(cap + 4).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "registry hive cell at offset {cur:#x} overflows the template"
                    ))
                })?;
            }
            bin = bin_end;
        }
        Ok(None)
    }

    /// The bin bounds containing file offset `file`.
    pub(crate) fn bin_bounds(&self, file: usize) -> Result<(usize, usize)> {
        let len = self.buf.len();
        let mut bin = BIN_BASE;
        while bin < len {
            let size = self.read_i32(bin + 8, "hive bin size")? as usize;
            let end = bin.checked_add(size).ok_or_else(|| {
                CoreError::invalid(format!(
                    "registry hive hive bin at offset {bin:#x} overflows the template"
                ))
            })?;
            if file >= bin && file < end {
                return Ok((bin, end));
            }
            bin = end;
        }
        Err(CoreError::invalid(format!(
            "bcd cell at file offset {file:#x} is in no hive bin"
        )))
    }

    /// Total free bytes across all bins, for shortage messages.
    pub(crate) fn free_space(&self) -> usize {
        let mut total = 0usize;
        let mut bin = BIN_BASE;
        while bin < self.buf.len() {
            let Ok(size) = self.read_i32(bin + 8, "hive bin size") else {
                break;
            };
            if size < BIN_SIZE as i32 || size % BIN_SIZE as i32 != 0 {
                break;
            }
            let bin_end = match bin.checked_add(size as usize) {
                Some(end) if end <= self.buf.len() => end,
                _ => break,
            };
            let mut cur = match bin.checked_add(HBIN_HEAD) {
                Some(cur) => cur,
                None => break,
            };
            while cur < bin_end {
                let Ok(raw) = self.read_i32(cur, "cell size") else {
                    break;
                };
                if raw == 0 {
                    break;
                }
                let cap = raw.unsigned_abs() as usize;
                if cap < MIN_CELL
                    || !cap.is_multiple_of(CELL_ROUND)
                    || cur.checked_add(cap).is_none()
                {
                    break;
                }
                if raw > 0 {
                    total = total.saturating_add(cap);
                }
                match cur.checked_add(cap) {
                    Some(next) => cur = next,
                    None => break,
                }
            }
            bin = bin_end;
        }
        total
    }

    /// Grow the list cell at file offset `file` (current total
    /// `old_total`) to `new_total` bytes using the free cell right
    /// after it. Returns `true` when the cell now holds `new_total`
    /// bytes (the absorbed region is zeroed; the caller rewrites the
    /// entries themselves); `false` means the caller must allocate a
    /// bigger list elsewhere. Used for both value lists and tag-bearing
    /// subkey lists.
    pub(crate) fn try_grow_in_place(
        &mut self,
        file: usize,
        old_total: usize,
        new_total: usize,
    ) -> Result<bool> {
        if new_total < old_total {
            return Err(CoreError::invalid(format!(
                "bcd list at file offset {file:#x} cannot shrink from {old_total} to {new_total} bytes"
            )));
        }
        let extra = new_total.saturating_sub(old_total);
        if extra == 0 {
            return Ok(true);
        }
        let (_, bin_end) = self.bin_bounds(file)?;
        let next = file.checked_add(old_total).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd list at file offset {file:#x} overflows growing"
            ))
        })?;
        if next >= bin_end {
            return Ok(false);
        }
        let raw = self.read_i32(next, "neighbour cell size")?;
        if raw <= 0 {
            return Ok(false);
        }
        let free = raw as usize;
        if free < extra {
            return Ok(false);
        }
        let rest = free.saturating_sub(extra);
        if rest != 0 && rest < MIN_CELL {
            return Ok(false);
        }
        let grown = i32::try_from(new_total).map_err(|_| {
            CoreError::invalid(format!(
                "registry hive has no room for a {new_total}-byte list"
            ))
        })?;
        self.store_at(file, &(-grown).to_le_bytes(), "grown list size")?;
        let absorbed = file.checked_add(old_total).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd list at file offset {file:#x} overflows zeroing"
            ))
        })?;
        self.zero_range(absorbed, extra)?;
        if rest == 0 {
            return Ok(true);
        }
        let free_file = next.checked_add(extra).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd list at file offset {file:#x} overflows splitting"
            ))
        })?;
        let rest_size = i32::try_from(rest).map_err(|_| {
            CoreError::invalid(format!(
                "registry hive has no room for a {rest}-byte free cell"
            ))
        })?;
        self.store_at(free_file, &rest_size.to_le_bytes(), "free cell size")?;
        self.zero_body(free_file, rest.saturating_sub(4))?;
        Ok(true)
    }

    /// Append one 4 KiB hive bin and account its size in the header.
    pub(crate) fn append_hbin(&mut self) -> Result<()> {
        let at = self.buf.len();
        if at < BIN_BASE || !at.is_multiple_of(BIN_SIZE) {
            return Err(CoreError::invalid(format!(
                "registry hive of {at} bytes cannot take an appended hive bin"
            )));
        }
        let end = at.checked_add(BIN_SIZE).ok_or_else(|| {
            CoreError::invalid("registry hive has no room for another 4 KiB hive bin".to_string())
        })?;
        self.buf.resize(end, 0);
        self.store_at(at, b"hbin", "appended hive bin magic")?;
        let prev = u32::try_from(at.saturating_sub(BIN_SIZE)).map_err(|_| {
            CoreError::invalid(format!(
                "registry hive offset {at:#x} does not fit the appended bin header"
            ))
        })?;
        self.store_u32(at + 4, prev, "appended hive bin offset")?;
        self.store_u32(at + 8, BIN_SIZE as u32, "appended hive bin size")?;
        let free = at.checked_add(HBIN_HEAD).ok_or_else(|| {
            CoreError::invalid(format!(
                "registry hive offset {at:#x} overflows the appended bin"
            ))
        })?;
        self.store_at(
            free,
            &(HBIN_USABLE as i32).to_le_bytes(),
            "appended bin free cell size",
        )?;
        let old_len = self.read_u32(HDR_BIN_LENGTH, "header hive-bin length")?;
        let new_len = old_len.checked_add(BIN_SIZE as u32).ok_or_else(|| {
            CoreError::invalid(
                "registry hive hive-bin length overflows appending a bin".to_string(),
            )
        })?;
        self.store_u32(HDR_BIN_LENGTH, new_len, "header hive-bin length")?;
        Ok(())
    }

    /// Release the data cell at `cell` back to free space, merging with
    /// free neighbours so the hive does not fragment.
    pub(crate) fn free_cell(&mut self, cell: usize) -> Result<()> {
        let mut file = Self::cell_file(cell, "free cell")?;
        let raw = self.read_i32(file, "free cell size")?;
        if raw < 0 {
            self.store_at(file, &(-raw).to_le_bytes(), "free cell size")?;
        }
        let (bin, bin_end) = self.bin_bounds(file)?;
        let mut total = self.read_i32(file, "free cell size")?.unsigned_abs() as usize;
        let mut start = file;
        let mut cur = bin.checked_add(HBIN_HEAD).ok_or_else(|| {
            CoreError::invalid(format!(
                "registry hive hive bin at offset {bin:#x} overflows the template"
            ))
        })?;
        let mut prev: Option<(usize, usize)> = None;
        while cur < bin_end {
            let cur_raw = self.read_i32(cur, "free cell size")?;
            let cur_total = cur_raw.unsigned_abs() as usize;
            if cur == start {
                break;
            }
            let next = cur.checked_add(cur_total).ok_or_else(|| {
                CoreError::invalid(format!(
                    "registry hive cell at offset {cur:#x} overflows the template"
                ))
            })?;
            if next == start {
                prev = Some((cur, cur_total));
                break;
            }
            cur = next;
            if cur_total == 0 {
                return Err(CoreError::invalid(format!(
                    "registry hive has a zero-size cell at offset {cur:#x}"
                )));
            }
        }
        if let Some((prev_file, prev_total)) = prev {
            let prev_raw = self.read_i32(prev_file, "free cell size")?;
            if prev_raw > 0 {
                let merged = prev_total.checked_add(total).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "bcd free cell at offset {prev_file:#x} overflows merging"
                    ))
                })?;
                let merged_i32 = i32::try_from(merged).map_err(|_| {
                    CoreError::invalid(format!(
                        "registry hive has no room for a {merged}-byte free cell"
                    ))
                })?;
                self.store_at(prev_file, &merged_i32.to_le_bytes(), "free cell size")?;
                start = prev_file;
                total = merged;
                file = prev_file;
            }
        }
        let next = start.checked_add(total).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd free cell at offset {start:#x} overflows merging"
            ))
        })?;
        if next < bin_end {
            let next_raw = self.read_i32(next, "neighbour cell size")?;
            if next_raw > 0 {
                let next_total = next_raw as usize;
                let merged = total.checked_add(next_total).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "bcd free cell at offset {start:#x} overflows merging"
                    ))
                })?;
                let merged_i32 = i32::try_from(merged).map_err(|_| {
                    CoreError::invalid(format!(
                        "registry hive has no room for a {merged}-byte free cell"
                    ))
                })?;
                self.store_at(start, &merged_i32.to_le_bytes(), "free cell size")?;
                let _ = file;
            }
        }
        Ok(())
    }

    /// Allocate a data cell holding `data`.
    pub(crate) fn new_data_cell(&mut self, data: &[u8]) -> Result<usize> {
        let body_len = data.len();
        u32::try_from(body_len).map_err(|_| {
            CoreError::invalid(format!(
                "registry hive has no room for a {body_len}-byte value"
            ))
        })?;
        let cell = self.alloc(body_len)?;
        let file = Self::cell_file(cell, "value data")?;
        self.store_at(
            file.checked_add(4).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd data cell at offset {cell:#x} overflows writing"
                ))
            })?,
            data,
            "value data",
        )?;
        Ok(cell)
    }

    /// Allocate a `vk` cell for `name` (must be ASCII) with `vtype`/`data`.
    pub(crate) fn new_vk(&mut self, name: &[u8], vtype: u32, data: &[u8]) -> Result<usize> {
        if !name.is_ascii() {
            return Err(CoreError::invalid(
                "bcd value names must stay plain ASCII".to_string(),
            ));
        }
        u32::try_from(data.len()).map_err(|_| {
            CoreError::invalid(format!(
                "registry hive has no room for a {}-byte value",
                data.len()
            ))
        })?;
        let cell = self.alloc(VK_FIXED + name.len())?;
        let file = Self::cell_file(cell, "value cell")?;
        let body = file.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!("bcd value at offset {cell:#x} overflows writing"))
        })?;
        self.store_at(body, b"vk", "value tag")?;
        self.store_u16(
            body.checked_add(0x02).ok_or_else(|| {
                CoreError::invalid(format!("bcd value at offset {cell:#x} overflows"))
            })?,
            name.len() as u16,
            "value name length",
        )?;
        if data.len() <= 4 {
            let mut inline = [0u8; 4];
            for (slot, byte) in inline.iter_mut().zip(data.iter()) {
                *slot = *byte;
            }
            let size = (data.len() as u32) | INLINE_FLAG;
            self.store_u32(
                body.checked_add(0x04).ok_or_else(|| {
                    CoreError::invalid(format!("bcd value at offset {cell:#x} overflows"))
                })?,
                size,
                "inline value data size",
            )?;
            self.store_at(
                body.checked_add(0x08).ok_or_else(|| {
                    CoreError::invalid(format!("bcd value at offset {cell:#x} overflows"))
                })?,
                &inline,
                "inline value data",
            )?;
        } else {
            let data_cell = u32::try_from(self.new_data_cell(data)?).map_err(|_| {
                CoreError::invalid(format!(
                    "bcd data cell at offset {cell:#x} does not fit the template"
                ))
            })?;
            self.store_u32(
                body.checked_add(0x04).ok_or_else(|| {
                    CoreError::invalid(format!("bcd value at offset {cell:#x} overflows"))
                })?,
                data.len() as u32,
                "value data size",
            )?;
            self.store_at(
                body.checked_add(0x08).ok_or_else(|| {
                    CoreError::invalid(format!("bcd value at offset {cell:#x} overflows"))
                })?,
                &data_cell.to_le_bytes(),
                "value data offset",
            )?;
        }
        self.store_u32(
            body.checked_add(0x0C).ok_or_else(|| {
                CoreError::invalid(format!("bcd value at offset {cell:#x} overflows"))
            })?,
            vtype,
            "value type",
        )?;
        self.store_u16(
            body.checked_add(0x10).ok_or_else(|| {
                CoreError::invalid(format!("bcd value at offset {cell:#x} overflows"))
            })?,
            VK_LATIN1,
            "value flags",
        )?;
        self.store_at(
            body.checked_add(VK_FIXED).ok_or_else(|| {
                CoreError::invalid(format!("bcd value at offset {cell:#x} overflows"))
            })?,
            name,
            "value name",
        )?;
        Ok(cell)
    }

    /// Overwrite the data of the value at `vk`: in place when the new
    /// data fits the old cell, inline (freeing the old cell) when it
    /// fits 4 bytes, otherwise a fresh data cell.
    pub(crate) fn set_value_data(&mut self, vk: usize, vtype: u32, data: &[u8]) -> Result<()> {
        u32::try_from(data.len()).map_err(|_| {
            CoreError::invalid(format!(
                "registry hive has no room for a {}-byte value",
                data.len()
            ))
        })?;
        let file = Self::cell_file(vk, "value")?;
        let body = file
            .checked_add(4)
            .ok_or_else(|| CoreError::invalid(format!("bcd value at offset {vk:#x} overflows")))?;
        let at = |field: usize| {
            body.checked_add(field)
                .ok_or_else(|| CoreError::invalid(format!("bcd value at offset {vk:#x} overflows")))
        };
        let raw_size = self.read_u32(at(0x04)?, "value data size")?;
        let was_inline = raw_size & INLINE_FLAG != 0;
        let old_cell = self.read_u32(at(0x08)?, "value data offset")? as usize;
        let old_cap = if was_inline {
            4
        } else {
            let old_file = Self::cell_file(old_cell, "old value data")?;
            Self::capacity(self.read_i32(old_file, "old value data size")?)
        };
        if data.len() <= 4 {
            let mut inline = [0u8; 4];
            for (slot, byte) in inline.iter_mut().zip(data.iter()) {
                *slot = *byte;
            }
            self.store_u32(
                at(0x04)?,
                (data.len() as u32) | INLINE_FLAG,
                "value data size",
            )?;
            self.store_at(at(0x08)?, &inline, "inline value data")?;
            self.store_u32(at(0x0C)?, vtype, "value type")?;
            if !was_inline {
                self.free_cell(old_cell)?;
            }
            return Ok(());
        }
        if !was_inline && data.len() <= old_cap {
            self.store_u32(at(0x04)?, data.len() as u32, "value data size")?;
            // The data offset field is unchanged: the data stays in its cell.
            let data_file = Self::cell_file(old_cell, "value data")?;
            let dest = data_file.checked_add(4).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd value at offset {vk:#x} overflows writing data"
                ))
            })?;
            self.store_at(dest, data, "value data")?;
            let pad = old_cap.saturating_sub(data.len());
            if pad > 0 {
                let pad_at = dest.checked_add(data.len()).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "bcd value at offset {vk:#x} overflows zeroing padding"
                    ))
                })?;
                self.store_at(pad_at, &vec![0u8; pad], "value padding")?;
            }
            self.store_u32(at(0x0C)?, vtype, "value type")?;
            return Ok(());
        }
        let cell = self.new_data_cell(data)?;
        let cell_u32 = u32::try_from(cell).map_err(|_| {
            CoreError::invalid(format!(
                "bcd data cell at offset {cell:#x} does not fit the template"
            ))
        })?;
        self.store_u32(at(0x04)?, data.len() as u32, "value data size")?;
        self.store_at(at(0x08)?, &cell_u32.to_le_bytes(), "value data offset")?;
        self.store_u32(at(0x0C)?, vtype, "value type")?;
        if !was_inline {
            self.free_cell(old_cell)?;
        }
        Ok(())
    }

    /// Add a new value `name` under `key`; refuses when it exists.
    pub(crate) fn add_value(
        &mut self,
        key: usize,
        name: &[u8],
        vtype: u32,
        data: &[u8],
    ) -> Result<usize> {
        if self.find_value(key, name)?.is_some() {
            let display = String::from_utf8_lossy(name);
            return Err(CoreError::invalid(format!(
                "bcd key at offset {key:#x} already has a value {display}"
            )));
        }
        let vk = self.new_vk(name, vtype, data)?;
        let nval = self.nk_u32(key, 0x24, "value count")?;
        if nval == 0 {
            let list = self.alloc(4)?;
            let file = Self::cell_file(list, "value list")?;
            let vk_u32 = u32::try_from(vk).map_err(|_| {
                CoreError::invalid(format!(
                    "bcd value at offset {vk:#x} does not fit the template"
                ))
            })?;
            self.store_at(
                file.checked_add(4).ok_or_else(|| {
                    CoreError::invalid(format!("bcd value list at offset {list:#x} overflows"))
                })?,
                &vk_u32.to_le_bytes(),
                "value list entry",
            )?;
            self.store_u32_cell(key, 0x24, 1, "value count")?;
            self.store_u32_cell(
                key,
                0x28,
                u32::try_from(list).map_err(|_| {
                    CoreError::invalid(format!(
                        "bcd value list at offset {list:#x} does not fit the template"
                    ))
                })?,
                "value list",
            )?;
            return Ok(vk);
        }
        let new_nval = nval.checked_add(1).ok_or_else(|| {
            CoreError::invalid(format!("bcd key at offset {key:#x} counts too many values"))
        })?;
        let new_total = Self::cell_total((new_nval as usize).checked_mul(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd key at offset {key:#x} counts {new_nval} values that overflow"
            ))
        })?)?;
        let old_list = self.nk_u32(key, 0x28, "value list")? as usize;
        let old_file = Self::cell_file(old_list, "value list")?;
        let old_raw = self.read_i32(old_file, "value list size")?;
        let old_total = old_raw.unsigned_abs() as usize;
        let entries = self.value_list(key)?;
        if !self.try_grow_in_place(old_file, old_total, new_total)? {
            let list = self.alloc((new_nval as usize).saturating_mul(4))?;
            let file = Self::cell_file(list, "value list")?;
            let mut at = file.checked_add(4).ok_or_else(|| {
                CoreError::invalid(format!("bcd value list at offset {list:#x} overflows"))
            })?;
            for entry in entries {
                let entry_u32 = u32::try_from(entry).map_err(|_| {
                    CoreError::invalid(format!(
                        "bcd value at offset {entry:#x} does not fit the template"
                    ))
                })?;
                self.store_at(at, &entry_u32.to_le_bytes(), "value list entry")?;
                at = at.checked_add(4).ok_or_else(|| {
                    CoreError::invalid(format!("bcd value list at offset {list:#x} overflows"))
                })?;
            }
            let vk_u32 = u32::try_from(vk).map_err(|_| {
                CoreError::invalid(format!(
                    "bcd value at offset {vk:#x} does not fit the template"
                ))
            })?;
            self.store_at(at, &vk_u32.to_le_bytes(), "value list entry")?;
            self.store_u32_cell(key, 0x24, new_nval, "value count")?;
            self.store_u32_cell(
                key,
                0x28,
                u32::try_from(list).map_err(|_| {
                    CoreError::invalid(format!(
                        "bcd value list at offset {list:#x} does not fit the template"
                    ))
                })?,
                "value list",
            )?;
            self.free_cell(old_list)?;
        } else {
            let slot = old_file
                .checked_add(4)
                .and_then(|base| {
                    (nval as usize)
                        .checked_mul(4)
                        .and_then(|n| base.checked_add(n))
                })
                .ok_or_else(|| {
                    CoreError::invalid(format!(
                        "bcd value list at offset {old_list:#x} entry {nval} overflows"
                    ))
                })?;
            let vk_u32 = u32::try_from(vk).map_err(|_| {
                CoreError::invalid(format!(
                    "bcd value at offset {vk:#x} does not fit the template"
                ))
            })?;
            self.store_at(slot, &vk_u32.to_le_bytes(), "value list entry")?;
            self.store_u32_cell(key, 0x24, new_nval, "value count")?;
        }
        Ok(vk)
    }

    /// Store a `u32` `nk` field at tag-relative `field`.
    pub(crate) fn store_u32_cell(
        &mut self,
        cell: usize,
        field: usize,
        value: u32,
        what: &str,
    ) -> Result<()> {
        let file = Self::cell_file(cell, what)?;
        let body = file.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd cell offset {cell:#x} overflows writing {what}"
            ))
        })?;
        let at = body.checked_add(field).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd cell offset {cell:#x} overflows writing {what}"
            ))
        })?;
        self.store_u32(at, value, what)
    }

    /// Add a subkey `name` under `parent`, cloning the fixed `nk` image
    /// of `model` when given (security descriptor and spare fields
    /// included) and inserting the entry sorted into the subkey list.
    pub(crate) fn add_child_key(
        &mut self,
        parent: usize,
        name: &[u8],
        model: Option<usize>,
    ) -> Result<usize> {
        if !name.is_ascii() || name.is_empty() {
            return Err(CoreError::invalid(
                "bcd key names must stay non-empty plain ASCII".to_string(),
            ));
        }
        if name.len() > u16::MAX as usize {
            return Err(CoreError::invalid(format!(
                "bcd key name is {} bytes, longer than the 16-bit length",
                name.len()
            )));
        }
        let mut fixed = [0u8; NK_FIXED];
        let mut sk = NONE;
        if let Some(model) = model {
            let model_file = Self::cell_file(model, "model key")?;
            fixed = self.read_at(
                model_file.checked_add(4).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "bcd model key at offset {model:#x} overflows reading"
                    ))
                })?,
                "model key image",
            )?;
            sk = self.nk_u32(model, 0x2C, "model key security")?;
        } else {
            write_field(&mut fixed, 0x00, b"nk", "key tag")?;
            write_field(&mut fixed, 0x02, &NK_COMPRESSED.to_le_bytes(), "key flags")?;
        }
        // Patch the identity fields; timestamps stay zeroed for fresh
        // keys so repeated builds are byte-deterministic. New names are
        // always ASCII (checked above), so pin the latin-1 flag instead of
        // inheriting the model sibling's flags byte.
        write_field(&mut fixed, 0x02, &NK_COMPRESSED.to_le_bytes(), "key flags")?;
        let parent_u32 = u32::try_from(parent).map_err(|_| {
            CoreError::invalid(format!(
                "bcd parent key at offset {parent:#x} does not fit the template"
            ))
        })?;
        write_field(&mut fixed, 0x04, &[0; 8], "key timestamp")?;
        write_field(&mut fixed, 0x10, &parent_u32.to_le_bytes(), "key parent")?;
        write_field(&mut fixed, 0x14, &0u32.to_le_bytes(), "subkey count")?;
        write_field(&mut fixed, 0x1C, &NONE.to_le_bytes(), "subkey list")?;
        write_field(&mut fixed, 0x24, &0u32.to_le_bytes(), "value count")?;
        write_field(&mut fixed, 0x28, &NONE.to_le_bytes(), "value list")?;
        write_field(&mut fixed, 0x2C, &sk.to_le_bytes(), "key security")?;
        write_field(
            &mut fixed,
            NK_NAMELEN,
            &(name.len() as u16).to_le_bytes(),
            "key name length",
        )?;
        let cell = self.alloc(NK_FIXED + name.len())?;
        let file = Self::cell_file(cell, "new key")?;
        self.store_at(
            file.checked_add(4).ok_or_else(|| {
                CoreError::invalid(format!("bcd key at offset {cell:#x} overflows writing"))
            })?,
            &fixed,
            "new key image",
        )?;
        self.store_at(
            file.checked_add(4 + NK_NAME).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd key at offset {cell:#x} overflows writing its name"
                ))
            })?,
            name,
            "new key name",
        )?;
        self.list_insert(parent, cell, name)?;
        Ok(cell)
    }

    /// Insert `child` into the subkey list of `parent`, sorted by name,
    /// growing the list in place when the neighbour cell allows it.
    pub(crate) fn list_insert(&mut self, parent: usize, child: usize, name: &[u8]) -> Result<()> {
        let nsub = self.nk_u32(parent, 0x14, "subkey count")?;
        let old_list = self.nk_u32(parent, 0x1C, "subkey list")?;
        let mut entries: Vec<(Vec<u8>, u32, u32)> = Vec::new();
        let mut tag = *b"lf";
        if nsub > 0 {
            if old_list == NONE {
                return Err(CoreError::invalid(format!(
                    "bcd key at offset {parent:#x} counts {nsub} subkeys but has no subkey list"
                )));
            }
            let list = old_list as usize;
            tag = self.cell_tag(list)?;
            let (count, entry_size, entries_off, hashed) = self.list_head(list)?;
            if count != nsub {
                return Err(CoreError::invalid(format!(
                    "bcd key at offset {parent:#x} counts {nsub} subkeys but its list holds {count}"
                )));
            }
            for index in 0..count {
                let at = (index as usize)
                    .checked_mul(entry_size)
                    .and_then(|n| entries_off.checked_add(n))
                    .ok_or_else(|| {
                        CoreError::invalid(format!(
                            "bcd subkey list at offset {list:#x} entry {index} overflows"
                        ))
                    })?;
                let off = self.read_u32(at, "subkey list entry")? as usize;
                let hash = if hashed {
                    self.read_u32(
                        at.checked_add(4).ok_or_else(|| {
                            CoreError::invalid(format!(
                                "bcd subkey list at offset {list:#x} entry {index} overflows"
                            ))
                        })?,
                        "subkey list hash",
                    )?
                } else {
                    0
                };
                let (stored, _) = self.nk_name(off)?;
                entries.push((stored, off as u32, hash));
            }
        }
        let child_u32 = u32::try_from(child).map_err(|_| {
            CoreError::invalid(format!(
                "bcd subkey at offset {child:#x} does not fit the template"
            ))
        })?;
        entries.push((name.to_vec(), child_u32, lf_hash(name)));
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let entry_size = if tag == *b"lf" || tag == *b"lh" { 8 } else { 4 };
        let new_nsub = nsub.checked_add(1).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd key at offset {parent:#x} counts too many subkeys"
            ))
        })?;
        let body_len = (new_nsub as usize)
            .checked_mul(entry_size)
            .and_then(|n| n.checked_add(LIST_ENTRIES))
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd key at offset {parent:#x} subkey list overflows"
                ))
            })?;
        let new_total = Self::cell_total(body_len)?;
        if nsub > 0 {
            let list = old_list as usize;
            let file = Self::cell_file(list, "subkey list")?;
            let old_raw = self.read_i32(file, "subkey list size")?;
            let old_total = old_raw.unsigned_abs() as usize;
            if self.try_grow_subkey_list(file, old_total, new_total)? {
                self.write_subkey_list(file, &tag, &entries)?;
                self.store_u32_cell(parent, 0x14, new_nsub, "subkey count")?;
                return Ok(());
            }
        }
        let list = self.alloc(body_len)?;
        let file = Self::cell_file(list, "subkey list")?;
        self.write_subkey_list(file, &tag, &entries)?;
        self.store_u32_cell(parent, 0x14, new_nsub, "subkey count")?;
        self.store_u32_cell(
            parent,
            0x1C,
            u32::try_from(list).map_err(|_| {
                CoreError::invalid(format!(
                    "bcd subkey list at offset {list:#x} does not fit the template"
                ))
            })?,
            "subkey list",
        )?;
        if nsub > 0 {
            self.free_cell(old_list as usize)?;
        }
        Ok(())
    }

    /// Grow a tag-bearing subkey list in place (same neighbour rules
    /// as value lists).
    pub(crate) fn try_grow_subkey_list(
        &mut self,
        file: usize,
        old_total: usize,
        new_total: usize,
    ) -> Result<bool> {
        if new_total < old_total {
            return Err(CoreError::invalid(format!(
                "bcd subkey list at file offset {file:#x} cannot shrink"
            )));
        }
        let extra = new_total.saturating_sub(old_total);
        if extra == 0 {
            return Ok(true);
        }
        let (_, bin_end) = self.bin_bounds(file)?;
        let next = file.checked_add(old_total).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd subkey list at file offset {file:#x} overflows growing"
            ))
        })?;
        if next >= bin_end {
            return Ok(false);
        }
        let raw = self.read_i32(next, "neighbour cell size")?;
        if raw <= 0 {
            return Ok(false);
        }
        let free = raw as usize;
        if free < extra {
            return Ok(false);
        }
        let rest = free.saturating_sub(extra);
        if rest != 0 && rest < MIN_CELL {
            return Ok(false);
        }
        let grown = i32::try_from(new_total).map_err(|_| {
            CoreError::invalid(format!(
                "registry hive has no room for a {new_total}-byte subkey list"
            ))
        })?;
        self.store_at(file, &(-grown).to_le_bytes(), "grown subkey list size")?;
        let absorbed = file.checked_add(old_total).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd subkey list at file offset {file:#x} overflows zeroing"
            ))
        })?;
        self.zero_range(absorbed, extra)?;
        if rest == 0 {
            return Ok(true);
        }
        let free_file = next.checked_add(extra).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd subkey list at file offset {file:#x} overflows splitting"
            ))
        })?;
        let rest_size = i32::try_from(rest).map_err(|_| {
            CoreError::invalid(format!(
                "registry hive has no room for a {rest}-byte free cell"
            ))
        })?;
        self.store_at(free_file, &rest_size.to_le_bytes(), "free cell size")?;
        self.zero_body(free_file, rest.saturating_sub(4))?;
        Ok(true)
    }

    /// Write a full subkey list body (tag, count, sorted entries).
    pub(crate) fn write_subkey_list(
        &mut self,
        file: usize,
        tag: &[u8; 2],
        entries: &[(Vec<u8>, u32, u32)],
    ) -> Result<()> {
        let count = u16::try_from(entries.len()).map_err(|_| {
            CoreError::invalid(format!(
                "bcd subkey list at file offset {file:#x} counts too many entries"
            ))
        })?;
        let hashed = tag == b"lf" || tag == b"lh";
        let body = file.checked_add(4).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd subkey list at file offset {file:#x} overflows writing"
            ))
        })?;
        self.store_at(body, tag, "subkey list tag")?;
        self.store_u16(
            body.checked_add(LIST_COUNT).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd subkey list at file offset {file:#x} overflows"
                ))
            })?,
            count,
            "subkey list count",
        )?;
        let mut at = body.checked_add(LIST_ENTRIES).ok_or_else(|| {
            CoreError::invalid(format!(
                "bcd subkey list at file offset {file:#x} overflows"
            ))
        })?;
        for (_, off, hash) in entries {
            self.store_u32(at, *off, "subkey list entry")?;
            at = at.checked_add(4).ok_or_else(|| {
                CoreError::invalid(format!(
                    "bcd subkey list at file offset {file:#x} overflows"
                ))
            })?;
            if hashed {
                self.store_u32(at, *hash, "subkey list hash")?;
                at = at.checked_add(4).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "bcd subkey list at file offset {file:#x} overflows"
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Ensure the `Elements\{id}` subkey exists, cloning the first
    /// sibling element as the `nk` model when there is one.
    pub(crate) fn ensure_element(&mut self, elements: usize, id: u32) -> Result<usize> {
        let name = element_name(id);
        if let Some(found) = self.find_child(elements, &name)? {
            return Ok(found);
        }
        let model = self.first_child(elements)?;
        let cell = self.add_child_key(elements, &name, model)?;
        Ok(cell)
    }

    /// Set one BCD element: ensure the `Elements\{id}` subkey, then
    /// set or add its `Element` value.
    pub(crate) fn set_element(
        &mut self,
        elements: usize,
        id: u32,
        vtype: u32,
        data: &[u8],
    ) -> Result<()> {
        let key = self.ensure_element(elements, id)?;
        match self.find_value(key, b"Element")? {
            Some(vk) => self.set_value_data(vk, vtype, data),
            None => {
                self.add_value(key, b"Element", vtype, data)?;
                Ok(())
            }
        }
    }

    /// Set a `REG_SZ` element from text.
    pub(crate) fn set_element_sz(&mut self, elements: usize, id: u32, text: &str) -> Result<()> {
        let data = utf16_nul(text);
        self.set_element(elements, id, REG_SZ, &data)
    }

    /// Set a `REG_MULTI_SZ` element from GUID strings.
    pub(crate) fn set_element_multisz(
        &mut self,
        elements: usize,
        id: u32,
        items: &[&str],
    ) -> Result<()> {
        let data = utf16_multisz(items);
        self.set_element(elements, id, REG_MULTI_SZ, &data)
    }

    /// Set a `REG_BINARY` element from raw bytes.
    pub(crate) fn set_element_binary(
        &mut self,
        elements: usize,
        id: u32,
        data: &[u8],
    ) -> Result<()> {
        self.set_element(elements, id, REG_BINARY, data)
    }

    /// Recompute the header checksum over the current bytes.
    pub(crate) fn update_checksum(&mut self) -> Result<()> {
        let computed = Self::header_checksum(&self.buf).ok_or_else(|| {
            CoreError::invalid("registry hive ends before the header checksum".to_string())
        })?;
        self.store_u32(HDR_CHECKSUM, computed, "header checksum")
    }

    /// Consume the hive into its bytes.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the hive bytes without consuming.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.buf.clone()
    }

    /// Find a key by a path of names from the root, one `find_child`
    /// step per part. An empty path names the root itself.
    pub(crate) fn find_path(&self, path: &[&[u8]]) -> Result<Option<usize>> {
        let mut current = self.root();
        for part in path.iter().copied() {
            let Some(next) = self.find_child(current, part)? else {
                return Ok(None);
            };
            current = next;
        }
        Ok(Some(current))
    }

    /// Read one named value under `key`: the (`type`, bytes) pair,
    /// following the data cell unless the value is inline.
    pub(crate) fn read_value(&self, key: usize, name: &[u8]) -> Result<Option<(u32, Vec<u8>)>> {
        let Some(vk) = self.find_value(key, name)? else {
            return Ok(None);
        };
        Ok(Some(self.value_data(vk)?))
    }

    /// Overwrite the data of an existing named value under `key`.
    /// Refuses with `InvalidInput` naming the value when it is absent;
    /// callers that create-on-absent use `add_value` for that path.
    pub(crate) fn set_value(
        &mut self,
        key: usize,
        name: &[u8],
        vtype: u32,
        data: &[u8],
    ) -> Result<()> {
        let Some(vk) = self.find_value(key, name)? else {
            let display = String::from_utf8_lossy(name);
            return Err(CoreError::invalid(format!(
                "bcd key at offset {key:#x} has no value {display} to update"
            )));
        };
        self.set_value_data(vk, vtype, data)
    }
}

/// Write `bytes` at `at` inside a fixed `nk` image under construction.
pub(crate) fn write_field<const N: usize>(
    image: &mut [u8; N],
    at: usize,
    bytes: &[u8],
    what: &str,
) -> Result<()> {
    let end = at
        .checked_add(bytes.len())
        .ok_or_else(|| CoreError::invalid(format!("bcd key image overflows writing {what}")))?;
    if end > N {
        return Err(CoreError::invalid(format!(
            "bcd key image is {N} bytes, too short for {what} at offset {at:#x}"
        )));
    }
    let Some(window) = image.get_mut(at..end) else {
        return Err(CoreError::invalid(format!(
            "bcd key image window vanished writing {what}"
        )));
    };
    window.copy_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid hive with trailing zero padding (like a real `SYSTEM` hive)
    /// must parse at its declared bin extent, not at the padded buffer
    /// length, so a later `append_hbin` lands right after the bins.
    #[test]
    fn padded_hive_parses_at_declared_extent_and_appends_without_hole() {
        // Minimal two-bin hive with a `ROOT` root, mirroring the `to_go`
        // fixtures: header declares 0x2000 bytes of bins, buffer is 0x3000.
        let mut buf = vec![0u8; 0x200];
        buf[0..4].copy_from_slice(b"regf");
        buf[4..8].copy_from_slice(&1u32.to_le_bytes());
        buf[8..12].copy_from_slice(&1u32.to_le_bytes());
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        buf[0x18..0x1C].copy_from_slice(&3u32.to_le_bytes());
        buf[HDR_ROOT..HDR_ROOT + 4].copy_from_slice(&0x20u32.to_le_bytes());
        buf[HDR_BIN_LENGTH..HDR_BIN_LENGTH + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        buf.resize(0x3000, 0);
        buf[0x1000..0x1004].copy_from_slice(b"hbin");
        buf[0x1004..0x1008].copy_from_slice(&0u32.to_le_bytes());
        buf[0x1008..0x100C].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[0x2000..0x2004].copy_from_slice(b"hbin");
        buf[0x2004..0x2008].copy_from_slice(&0u32.to_le_bytes());
        buf[0x2008..0x200C].copy_from_slice(&0x1000u32.to_le_bytes());
        let root_file = 0x1020usize;
        buf[root_file..root_file + 4].copy_from_slice(&(-88i32).to_le_bytes());
        buf[root_file + 4..root_file + 6].copy_from_slice(b"nk");
        buf[root_file + 6..root_file + 8].copy_from_slice(&NK_COMPRESSED.to_le_bytes());
        buf[root_file + 0x14..root_file + 0x18].copy_from_slice(&NONE.to_le_bytes());
        buf[root_file + 0x20..root_file + 0x24].copy_from_slice(&NONE.to_le_bytes());
        buf[root_file + 0x2C..root_file + 0x30].copy_from_slice(&NONE.to_le_bytes());
        buf[root_file + 0x34..root_file + 0x38].copy_from_slice(&NONE.to_le_bytes());
        buf[root_file + 0x4C..root_file + 0x4E].copy_from_slice(&4u16.to_le_bytes());
        buf[root_file + 0x50..root_file + 0x54].copy_from_slice(b"ROOT");
        let free_file = root_file + 88;
        let free_size = 0x1000u32 - 0x20 - 88;
        buf[free_file..free_file + 4].copy_from_slice(&(free_size as i32).to_le_bytes());
        let free2 = 0x2020usize;
        buf[free2..free2 + 4].copy_from_slice(&(HBIN_USABLE as i32).to_le_bytes());
        let checksum = Hive::header_checksum(&buf).expect("fixture header must checksum");
        buf[HDR_CHECKSUM..HDR_CHECKSUM + 4].copy_from_slice(&checksum.to_le_bytes());

        // Trailing zero padding past the declared bins, like the real
        // `SYSTEM` hive's 242 176 bytes of zeros.
        let mut padded = buf.clone();
        padded.extend_from_slice(&vec![0u8; 8192]);
        assert!(padded.len() > BIN_BASE + 0x2000);

        let mut hive = Hive::parse(&padded).expect("padded hive must parse");
        // The in-memory extent is the declared bins, not the padded buffer.
        assert_eq!(hive.to_bytes().len(), BIN_BASE + 0x2000);
        assert_eq!(
            hive.read_u32(HDR_BIN_LENGTH, "header hive-bin length")
                .expect("bin length must read"),
            0x2000
        );
        assert!(hive.free_space() > 0);
        hive.check_bins().expect("declared bins must tile");

        // Appending must land right after the declared bins, leaving no hole.
        hive.append_hbin().expect("append must succeed");
        let out = hive.to_bytes();
        assert_eq!(out.len(), BIN_BASE + 0x3000);
        assert_eq!(&out[0x3000..0x3004], b"hbin");
        assert_eq!(
            u32::from_le_bytes(
                out[HDR_BIN_LENGTH..HDR_BIN_LENGTH + 4]
                    .try_into()
                    .expect("len")
            ),
            0x3000
        );
        hive.update_checksum().expect("checksum must store");
        Hive::parse(&hive.to_bytes()).expect("appended hive must re-parse");
    }
}
