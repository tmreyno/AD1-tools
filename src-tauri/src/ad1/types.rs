//! Type definitions for AD1 container format

use serde::Serialize;

/// Segment header information (public view)
#[derive(Serialize)]
pub struct SegmentHeaderInfo {
    pub signature: String,
    pub segment_index: u32,
    pub segment_number: u32,
    pub fragments_size: u32,
    pub header_size: u32,
}

/// Logical header information (public view)
#[derive(Serialize)]
pub struct LogicalHeaderInfo {
    pub signature: String,
    pub image_version: u32,
    pub zlib_chunk_size: u32,
    pub logical_metadata_addr: u64,
    pub first_item_addr: u64,
    pub data_source_name_length: u32,
    pub ad_signature: String,
    pub data_source_name_addr: u64,
    pub attrguid_footer_addr: u64,
    pub locsguid_footer_addr: u64,
    pub data_source_name: String,
}

/// Volume information from AD1 header
#[derive(Serialize, Clone, Default)]
pub struct VolumeInfo {
    pub volume_label: Option<String>,
    pub filesystem: Option<String>,
    pub os_info: Option<String>,
    pub block_size: Option<u32>,
    pub volume_serial: Option<String>,
}

/// Companion log file metadata (.ad1.txt)
#[derive(Serialize, Clone, Default)]
pub struct CompanionLogInfo {
    pub case_number: Option<String>,
    pub evidence_number: Option<String>,
    pub examiner: Option<String>,
    pub notes: Option<String>,
    pub md5_hash: Option<String>,
    pub sha1_hash: Option<String>,
    pub acquisition_date: Option<String>,
}

/// File/folder entry in the AD1 tree
#[derive(Serialize)]
pub struct TreeEntry {
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub item_type: u32,
}

/// Verification result entry
#[derive(Serialize)]
pub struct VerifyEntry {
    pub path: String,
    pub status: String,
    /// The hash algorithm used (e.g., "md5", "sha1")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// The computed hash value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computed: Option<String>,
    /// The stored hash value from AD1 metadata (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored: Option<String>,
    /// File size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Complete AD1 container information
#[derive(Serialize)]
pub struct Ad1Info {
    pub segment: SegmentHeaderInfo,
    pub logical: LogicalHeaderInfo,
    pub item_count: u64,
    pub tree: Option<Vec<TreeEntry>>,
    pub segment_files: Option<Vec<String>>,
    /// Size of each segment file in bytes
    pub segment_sizes: Option<Vec<u64>>,
    /// Total size of all segment files combined
    pub total_size: Option<u64>,
    /// Missing segment files (incomplete container)
    pub missing_segments: Option<Vec<String>>,
    pub volume: Option<VolumeInfo>,
    pub companion_log: Option<CompanionLogInfo>,
}

// =============================================================================
// Internal Types (used by parser and operations)
// =============================================================================

/// Internal segment header structure
#[derive(Clone)]
pub(crate) struct SegmentHeader {
    pub signature: [u8; 16],
    pub segment_index: u32,
    pub segment_number: u32,
    pub fragments_size: u32,
    pub header_size: u32,
}

/// Internal logical header structure  
#[derive(Clone)]
pub(crate) struct LogicalHeader {
    pub signature: [u8; 16],
    pub image_version: u32,
    pub zlib_chunk_size: u32,
    pub logical_metadata_addr: u64,
    pub first_item_addr: u64,
    pub data_source_name_length: u32,
    pub ad_signature: [u8; 4],
    pub data_source_name_addr: u64,
    pub attrguid_footer_addr: u64,
    pub locsguid_footer_addr: u64,
    pub data_source_name: String,
}

/// Item metadata entry
#[derive(Clone)]
pub(crate) struct Metadata {
    pub next_metadata_addr: u64,
    pub category: u32,
    pub key: u32,
    pub data: Vec<u8>,
}

/// Item in the AD1 tree (file or folder)
#[derive(Clone)]
pub(crate) struct Item {
    pub id: u64,
    pub name: String,
    pub item_type: u32,
    pub decompressed_size: u64,
    pub zlib_metadata_addr: u64,
    pub metadata: Vec<Metadata>,
    pub children: Vec<Item>,
}

// =============================================================================
// Constants
// =============================================================================

pub(crate) const AD1_SIGNATURE: &[u8; 15] = b"ADSEGMENTEDFILE";
pub(crate) const AD1_LOGICAL_MARGIN: u64 = 512;
pub(crate) const AD1_FOLDER_SIGNATURE: u32 = 0x05;
pub(crate) const CACHE_SIZE: usize = 100;
pub(crate) const SEGMENT_BLOCK_SIZE: u64 = 65_536;

// Metadata categories
pub(crate) const HASH_INFO: u32 = 0x01;
pub(crate) const TIMESTAMP: u32 = 0x05;

// Hash keys
pub(crate) const MD5_HASH: u32 = 0x5001;
pub(crate) const SHA1_HASH: u32 = 0x5002;

// Timestamp keys
pub(crate) const ACCESS: u32 = 0x07;
pub(crate) const MODIFIED: u32 = 0x08;
