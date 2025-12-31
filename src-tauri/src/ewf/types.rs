//! Type definitions for EWF format parsing

use serde::Serialize;

// =============================================================================
// Core Constants
// =============================================================================

pub(crate) const EWF_SIGNATURE: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";
pub(crate) const EWF2_SIGNATURE: &[u8; 8] = b"EVF2\x0d\x0a\x81\x00";
#[allow(dead_code)]
pub(crate) const SECTOR_SIZE: u64 = 512;
pub(crate) const MAX_OPEN_FILES: usize = 16; // Like libewf's rlimit handling

// =============================================================================
// Stored Hash Types - Hashes embedded in EWF file headers
// =============================================================================

#[derive(Serialize, Clone, Debug)]
pub struct StoredImageHash {
    pub algorithm: String,
    pub hash: String,
    pub timestamp: Option<String>,  // When hash was created (from acquiry_date)
    pub source: Option<String>,     // Source: "container" for embedded hashes
}

// =============================================================================
// Section Descriptors - EWF Format Structures
// =============================================================================

#[derive(Clone, Debug)]
pub(crate) struct SectionDescriptor {
    pub section_type: [u8; 16],
    pub next_offset: u64,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct VolumeSection {
    pub chunk_count: u32,
    pub sectors_per_chunk: u32,
    pub bytes_per_sector: u32,
    pub sector_count: u64,
    pub compression_level: u8,
}

// =============================================================================
// Segment File - Represents one physical E01/E02 file
// =============================================================================

/// Metadata for a single segment file (like libewf_segment_file)
pub(crate) struct SegmentFile {
    /// Index in the file pool
    pub file_index: usize,
    /// Segment number (1 for E01, 2 for E02, etc.)
    #[allow(dead_code)]
    pub segment_number: u16,
    /// Size of this segment file in bytes
    pub file_size: u64,
    /// Sections found in this segment
    pub sections: Vec<SegmentSection>,
}

#[derive(Clone)]
pub(crate) struct SegmentSection {
    #[allow(dead_code)]
    pub section_type: String,
    /// Offset within the segment file
    #[allow(dead_code)]
    pub offset_in_segment: u64,
    /// Size of section data
    #[allow(dead_code)]
    pub size: u64,
    /// For 'sectors' sections - where chunk data starts
    pub data_offset: Option<u64>,
    /// For 'table' sections - parsed table data
    pub table_data: Option<TableSection>,
}

#[derive(Clone)]
pub(crate) struct TableSection {
    #[allow(dead_code)]
    pub chunk_count: u32,
    pub base_offset: u64,
    /// Offsets are relative to the most recent 'sectors' section
    pub offsets: Vec<u64>,
}

// =============================================================================
// Chunk Location - Maps chunks to their storage location
// =============================================================================

#[derive(Clone)]
pub(crate) struct ChunkLocation {
    pub segment_index: usize,
    #[allow(dead_code)]
    pub section_index: usize, // Which 'sectors' section in this segment
    #[allow(dead_code)]
    pub chunk_in_table: usize,
    pub offset: u64, // The offset value from the table (may be relative to base_offset or absolute)
    pub base_offset: u64, // Table base offset for EnCase 6+ (0 for older versions)
    pub sectors_base: u64, // Global offset of the sectors section data area
    pub is_delta_chunk: bool, // True if this was scanned from inline delta format
}

// =============================================================================
// Public API Types
// =============================================================================

#[derive(Serialize)]
pub struct E01Info {
    pub format_version: String,
    pub segment_count: u32,
    pub chunk_count: u32,
    pub sector_count: u64,
    pub bytes_per_sector: u32,
    pub sectors_per_chunk: u32,
    pub total_size: u64,
    pub compression: String,
    pub case_number: Option<String>,
    pub description: Option<String>,
    pub examiner_name: Option<String>,
    pub evidence_number: Option<String>,
    pub notes: Option<String>,
    pub acquiry_date: Option<String>,
    pub system_date: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub stored_hashes: Vec<StoredImageHash>,
    pub segment_files: Option<Vec<String>>,
}

/// VerifyEntry for container verification results
#[derive(Serialize)]
pub struct VerifyResult {
    pub chunk_index: usize,
    pub status: String,
    pub message: Option<String>,
}
