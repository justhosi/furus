//! Checked sector arithmetic, human sizes and durations (S02).
//!
//! Sector math uses checked operations: a `u64` overflow is reported as
//! [`CoreError::InvalidInput`] instead of wrapping, because a wrapped byte
//! count could target the wrong device region downstream.

use std::time::Duration;

use crate::error::CoreError;
use crate::error::Result;

/// `sectors * sector_size`, checked.
///
/// Returns [`CoreError::InvalidInput`] on overflow.
pub fn sectors_to_bytes(sectors: u64, sector_size: u32) -> Result<u64> {
    sectors.checked_mul(u64::from(sector_size)).ok_or_else(|| {
        CoreError::invalid(format!(
            "sector count {sectors} x size {sector_size} overflows u64"
        ))
    })
}

/// `ceil(bytes / sector_size)` without overflow (division first, then a
/// conditional increment — no `bytes + sector_size - 1` addition).
///
/// `sector_size == 0` returns [`CoreError::InvalidInput`].
pub fn bytes_to_sectors_ceil(bytes: u64, sector_size: u32) -> Result<u64> {
    if sector_size == 0 {
        return Err(CoreError::invalid("sector size must not be zero"));
    }
    let size = u64::from(sector_size);
    Ok(bytes / size + u64::from(!bytes.is_multiple_of(size)))
}

/// `1023` → `"1023 B"`, `1536` → `"1.50 KiB"`, caps at TiB (larger values
/// are expressed as fractional TiB).
pub fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1_024.0;
    const MIB: f64 = 1_024.0 * 1_024.0;
    const GIB: f64 = 1_024.0 * 1_024.0 * 1_024.0;
    const TIB: f64 = 1_024.0 * 1_024.0 * 1_024.0 * 1_024.0;
    let value = bytes as f64;
    if bytes < 1_024 {
        format!("{bytes} B")
    } else if bytes < 1_048_576 {
        format!("{:.2} KiB", value / KIB)
    } else if bytes < 1_073_741_824 {
        format!("{:.2} MiB", value / MIB)
    } else if bytes < 1_099_511_627_776 {
        format!("{:.2} GiB", value / GIB)
    } else {
        format!("{:.2} TiB", value / TIB)
    }
}

/// `65s` → `"1:05"`, `3661s` → `"1:01:01"`; sub-second precision is
/// truncated, matching a progress-display use.
pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let hours = secs / 3_600;
    let minutes = (secs % 3_600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sectors_to_bytes_exact_and_overflow() {
        assert_eq!(sectors_to_bytes(1, 512).expect("small"), 512);
        assert_eq!(sectors_to_bytes(0, 4096).expect("zero"), 0);
        assert_eq!(
            sectors_to_bytes(8, 512).expect("typical"),
            4_096,
            "floppy-sized sanity check"
        );

        let too_many = u64::MAX / 512 + 1;
        let err = sectors_to_bytes(too_many, 512).expect_err("must overflow");
        assert!(err.to_string().contains("overflows"), "{err}");
        assert!(sectors_to_bytes(u64::MAX, 512).is_err());
        // Just under the edge still works.
        assert!(sectors_to_bytes(u64::MAX / 512, 512).is_ok());
    }

    #[test]
    fn sectors_ceil_rounds_up_without_overflow() {
        assert_eq!(bytes_to_sectors_ceil(0, 512).expect("zero"), 0);
        assert_eq!(bytes_to_sectors_ceil(1, 512).expect("one"), 1);
        assert_eq!(bytes_to_sectors_ceil(512, 512).expect("exact"), 1);
        assert_eq!(bytes_to_sectors_ceil(513, 512).expect("ceil"), 2);
        assert_eq!(bytes_to_sectors_ceil(u64::MAX, 1).expect("max"), u64::MAX);
        // ceil(u64::MAX / 4096): the naive `bytes + size - 1` would overflow.
        let want = u64::MAX / 4_096 + 1;
        assert_eq!(bytes_to_sectors_ceil(u64::MAX, 4096).expect("max"), want);
        assert!(bytes_to_sectors_ceil(100, 0).is_err());
    }

    #[test]
    fn human_bytes_boundaries() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1), "1 B");
        assert_eq!(human_bytes(1_023), "1023 B");
        assert_eq!(human_bytes(1_024), "1.00 KiB");
        assert_eq!(human_bytes(1_536), "1.50 KiB");
        assert_eq!(human_bytes(1_500), "1.46 KiB");
        assert_eq!(human_bytes(1_048_576), "1.00 MiB");
        assert_eq!(human_bytes(1_073_741_824), "1.00 GiB");
        assert_eq!(human_bytes(1_099_511_627_776), "1.00 TiB");
        assert_eq!(human_bytes(32_109_281_280), "29.90 GiB");
        assert_eq!(human_bytes(u64::MAX), "16777216.00 TiB");
    }

    #[test]
    fn duration_formats() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0:00");
        assert_eq!(format_duration(Duration::from_secs(5)), "0:05");
        assert_eq!(format_duration(Duration::from_secs(65)), "1:05");
        assert_eq!(format_duration(Duration::from_secs(3_661)), "1:01:01");
        assert_eq!(
            format_duration(Duration::from_millis(1_500)),
            "0:01",
            "sub-second precision is truncated"
        );
    }
}
