//! `rufus-proto`: versioned plan/progress types shared by the GUI, the CLI
//! and the privileged helper.
//!
//! Slice S01 only: plain placeholder structs with no serialisation.
//! `serde` derives and the JSON wire format arrive in S06.

/// Protocol version. Bump when the shape of [`Plan`] changes.
pub const PROTOCOL_VERSION: u32 = 1;

/// A validated write plan. Fields are placeholders; S06 defines the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Must equal [`PROTOCOL_VERSION`].
    pub version: u32,
    /// Target device path, e.g. `/dev/sdb`.
    pub device_path: String,
    /// Ordered operations to execute.
    pub steps: Vec<Step>,
}

/// One operation of a [`Plan`]. Variants are placeholders for S06+.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Zero first/last MiB and rescan partitions.
    Wipe,
}

/// Progress report for one running step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    /// Index into [`Plan::steps`] of the running step.
    pub step: usize,
    /// Total number of steps.
    pub total_steps: usize,
    /// Bytes completed within the running step.
    pub bytes_done: u64,
}

/// One log line emitted while a plan runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Severity label, e.g. `"info"`.
    pub level: String,
    /// Human-readable message.
    pub message: String,
}
