//! Archive container support (7z, ZIP, RAR)
//!
//! This module provides archive detection and metadata extraction for common
//! archive formats used in forensic workflows. Based on format specifications:
//!
//! ## ZIP Format
//! - Layout: [Local Headers][Data][Central Directory][EOCD]
//! - Metadata authority: Central Directory (not Local File Headers)
//! - ZIP64: Triggered when any value == 0xFFFFFFFF
//! - Signatures: PK\x03\x04 (Local), PK\x01\x02 (Central), PK\x05\x06 (EOCD)
//!
//! ## 7-Zip Format
//! - Signature: 37 7A BC AF 27 1C
//! - Layout: [Signature][Start Header][Compressed Streams][Main Header]
//! - Encrypted headers hide filenames and directory structure
//!
//! ## RAR Format
//! - RAR4: 52 61 72 21 1A 07 00
//! - RAR5: 52 61 72 21 1A 07 01 00
//!
//! ## Forensic Notes
//! - Container hash = metadata + payload (chain-of-custody)
//! - CRC32 is for error-detection, NOT tamper resistance
//! - Use cryptographic hashes (SHA-256) for evidentiary integrity
//!
//! ## Module Structure
//! ```text
//! archive/
//! ├── mod.rs        - Main entry point, info() function
//! ├── types.rs      - ArchiveFormat, ArchiveInfo
//! ├── detection.rs  - Magic signatures, format detection
//! ├── sevenz.rs     - 7-Zip header parsing, CRC
//! ├── zip.rs        - ZIP/ZIP64 EOCD parsing
//! └── segments.rs   - Multi-part archive discovery
//! ```
//!
//! Note: UFED detection in ZIPs is handled by `ufed::archive_scan`

pub mod types;
pub mod detection;
pub mod sevenz;
pub mod zip;
pub mod segments;

// Re-exports for convenience
pub use types::{ArchiveFormat, ArchiveInfo};
pub use detection::{is_archive, detect_archive_format, is_7z_segment};
// Note: is_first_segment, is_continuation_segment are in containers::segments
// which provides unified handling for all container types

use std::path::Path;
use tracing::debug;

/// Get archive information including segment discovery
pub fn info(path: &str) -> Result<ArchiveInfo, String> {
    debug!(path = %path, "Getting archive info");
    
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("Archive file not found: {path}"));
    }
    
    let format = detection::detect_archive_format(path)?
        .ok_or_else(|| format!("Unable to detect archive format: {path}"))?;
    
    let format_str = format.to_string();
    
    // Discover segments for multi-part archives
    let (segment_names, segment_sizes) = segments::discover_segments(path, format)?;
    let segment_count = segment_names.len() as u32;
    let total_size: u64 = segment_sizes.iter().sum();
    
    let first_segment = segment_names.first().cloned().unwrap_or_default();
    let last_segment = segment_names.last().cloned().unwrap_or_default();
    let is_multipart = segment_count > 1;
    
    // Parse format-specific metadata
    let (entry_count, central_dir_offset, central_dir_size, mut encrypted_headers, aes_encrypted) = 
        match format {
            ArchiveFormat::Zip | ArchiveFormat::Zip64 => {
                let meta = zip::parse_metadata(path).unwrap_or_default();
                (meta.entry_count, meta.central_dir_offset, meta.central_dir_size, 
                 meta.encrypted_headers, meta.aes_encrypted)
            }
            _ => (None, None, None, false, false),
        };
    
    // Parse 7z-specific metadata with full Start Header details
    let (next_header_offset, next_header_size, version, start_header_crc_valid, next_header_crc, sevenz_encrypted) = 
        match format {
            ArchiveFormat::SevenZip => {
                let meta = sevenz::parse_metadata(path).unwrap_or_default();
                (meta.next_header_offset, meta.next_header_size, meta.version,
                 meta.start_header_crc_valid, meta.next_header_crc, meta.encrypted)
            }
            _ => (None, None, None, None, None, false),
        };
    
    // Set encrypted_headers for 7z if detected
    if sevenz_encrypted {
        encrypted_headers = true;
    }
    
    // Detect UFED files (UFDR/UFDX/UFD) inside the archive
    let (ufed_detected, ufed_files) = match format {
        ArchiveFormat::Zip | ArchiveFormat::Zip64 => {
            crate::ufed::detect_in_zip(path).unwrap_or((false, vec![]))
        }
        _ => (false, vec![]),
    };
    
    debug!(
        path = %path,
        format = %format_str,
        segment_count = segment_count,
        total_size = total_size,
        entry_count = ?entry_count,
        ufed_detected = ufed_detected,
        "Archive info loaded"
    );
    
    Ok(ArchiveInfo {
        format: format_str,
        segment_count,
        total_size,
        segment_names,
        segment_sizes,
        first_segment,
        last_segment,
        is_multipart,
        entry_count,
        encrypted_headers,
        aes_encrypted,
        central_dir_offset,
        central_dir_size,
        next_header_offset,
        next_header_size,
        version,
        start_header_crc_valid,
        next_header_crc,
        ufed_detected,
        ufed_files,
    })
}
