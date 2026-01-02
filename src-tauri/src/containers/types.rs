//! Type definitions for forensic containers
//!
//! This module contains all the shared types used across the container subsystem.

use serde::{Serialize, Deserialize};

use crate::ad1;
use crate::archive;
use crate::ewf;
use crate::raw;
use crate::ufed;

/// Stored hash from container metadata or companion log files
#[derive(Serialize, Clone)]
pub struct StoredHash {
    pub algorithm: String,
    pub hash: String,
    /// None if not verified, Some(true) if verified, Some(false) if mismatch
    pub verified: Option<bool>,
    /// When hash was created/verified (ISO 8601 or human-readable)
    pub timestamp: Option<String>,
    /// Where hash came from: "container", "companion", "computed"
    pub source: Option<String>,
}

/// Per-segment hash information from companion log files
#[derive(Serialize, Deserialize, Clone)]
pub struct SegmentHash {
    /// e.g., "SCHARDT.001"
    pub segment_name: String,
    /// e.g., 1
    pub segment_number: u32,
    /// e.g., "MD5"
    pub algorithm: String,
    /// The hash value
    pub hash: String,
    /// Starting byte/sector offset
    pub offset_from: Option<u64>,
    /// Ending byte/sector offset
    pub offset_to: Option<u64>,
    /// Segment size
    pub size: Option<u64>,
    /// Verification status
    pub verified: Option<bool>,
}

/// Information parsed from companion log files (e.g., FTK logs, Guymager logs)
#[derive(Serialize, Clone)]
pub struct CompanionLogInfo {
    pub log_path: String,
    pub created_by: Option<String>,
    pub case_number: Option<String>,
    pub evidence_number: Option<String>,
    pub unique_description: Option<String>,
    pub examiner: Option<String>,
    pub notes: Option<String>,
    pub acquisition_started: Option<String>,
    pub acquisition_finished: Option<String>,
    pub verification_started: Option<String>,
    pub verification_finished: Option<String>,
    pub stored_hashes: Vec<StoredHash>,
    pub segment_list: Vec<String>,
    /// Per-segment hashes
    pub segment_hashes: Vec<SegmentHash>,
}

/// Unified container information structure
/// Holds format-specific info in the appropriate field
#[derive(Serialize)]
pub struct ContainerInfo {
    pub container: String,
    pub ad1: Option<ad1::Ad1Info>,
    /// EWF physical image (E01/Ex01)
    pub e01: Option<ewf::EwfInfo>,
    /// EWF logical evidence (L01/Lx01) - same format as E01
    pub l01: Option<ewf::EwfInfo>,
    pub raw: Option<raw::RawInfo>,
    pub archive: Option<archive::ArchiveInfo>,
    pub ufed: Option<ufed::UfedInfo>,
    pub note: Option<String>,
    pub companion_log: Option<CompanionLogInfo>,
}

/// Represents a discovered forensic container file during directory scanning
#[derive(Clone, Serialize)]
pub struct DiscoveredFile {
    pub path: String,
    pub filename: String,
    pub container_type: String,
    pub size: u64,
    pub segment_count: Option<u32>,
    pub segment_files: Option<Vec<String>>,
    pub segment_sizes: Option<Vec<u64>>,
    pub total_segment_size: Option<u64>,
    pub created: Option<String>,
    pub modified: Option<String>,
}

/// Result entry from container verification
#[derive(Serialize)]
pub struct VerifyEntry {
    pub path: Option<String>,
    pub chunk_index: Option<usize>,
    pub status: String,
    pub message: Option<String>,
}

/// Internal enum for container type detection
#[derive(Clone, Copy, Debug)]
pub(crate) enum ContainerKind {
    Ad1,
    E01,
    L01,
    Raw,
    Archive,
    Ufed,
}
