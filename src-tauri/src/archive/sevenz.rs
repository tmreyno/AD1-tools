//! 7-Zip format parsing
//!
//! Provides metadata extraction for 7-Zip archives based on the 7z specification.
//!
//! ## 7z Signature Header Layout (32 bytes total)
//!
//! | Offset | Size | Field              | Notes                                |
//! |--------|------|--------------------|--------------------------------------|
//! | 0x00   | 6    | Signature          | 37 7A BC AF 27 1C                   |
//! | 0x06   | 2    | Version            | major (1 byte), minor (1 byte)      |
//! | 0x08   | 4    | Start Header CRC   | CRC32 of bytes 0x0C-0x1F            |
//! | 0x0C   | 8    | Next Header Offset | Relative to byte 0x20               |
//! | 0x14   | 8    | Next Header Size   |                                      |
//! | 0x1C   | 4    | Next Header CRC    |                                      |

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use tracing::debug;

use super::detection::SEVEN_ZIP_MAGIC;

// =============================================================================
// 7z Header Type IDs
// =============================================================================

/// 7z Header Type IDs (first byte of Next Header determines meaning)
#[allow(dead_code)]
pub mod header_types {
    pub const END: u8 = 0x00;
    pub const HEADER: u8 = 0x01;
    pub const ARCHIVE_PROPERTIES: u8 = 0x02;
    pub const ADDITIONAL_STREAMS_INFO: u8 = 0x03;
    pub const MAIN_STREAMS_INFO: u8 = 0x04;
    pub const FILES_INFO: u8 = 0x05;
    pub const ENCODED_HEADER: u8 = 0x17;  // Indicates compressed/encrypted metadata
}

// =============================================================================
// Metadata Parsing
// =============================================================================

/// 7z metadata result
pub struct SevenZipMetadata {
    pub next_header_offset: Option<u64>,
    pub next_header_size: Option<u64>,
    pub version: Option<String>,
    pub start_header_crc_valid: Option<bool>,
    pub next_header_crc: Option<u32>,
    pub encrypted: bool,
}

impl Default for SevenZipMetadata {
    fn default() -> Self {
        Self {
            next_header_offset: None,
            next_header_size: None,
            version: None,
            start_header_crc_valid: None,
            next_header_crc: None,
            encrypted: false,
        }
    }
}

/// Parse 7-Zip Start Header and Next Header metadata
/// 
/// Returns metadata structure with header offsets, version, CRC validation, and encryption status.
pub fn parse_metadata(path: &str) -> Result<SevenZipMetadata, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open 7z: {e}"))?;
    
    let mut header = [0u8; 32];
    file.read_exact(&mut header)
        .map_err(|e| format!("Failed to read 7z header: {e}"))?;
    
    // Verify signature (6 bytes at offset 0)
    if &header[..6] != SEVEN_ZIP_MAGIC {
        return Ok(SevenZipMetadata::default());
    }
    
    // Parse version (2 bytes at offset 6: major, minor)
    let version_major = header[6];
    let version_minor = header[7];
    let version = Some(format!("{}.{}", version_major, version_minor));
    
    // Parse Start Header CRC (4 bytes at offset 8)
    // This CRC covers bytes 0x0C to 0x1F (20 bytes: next header offset, size, and CRC)
    let stored_start_crc = u32::from_le_bytes(header[8..12].try_into().unwrap());
    let computed_start_crc = crc32(&header[12..32]);
    let start_header_crc_valid = Some(stored_start_crc == computed_start_crc);
    
    // Parse Next Header Offset (8 bytes at offset 0x0C)
    // This is relative to byte 0x20 (end of signature header)
    let next_offset_relative = u64::from_le_bytes(header[12..20].try_into().unwrap());
    
    // Parse Next Header Size (8 bytes at offset 0x14)
    let next_size = u64::from_le_bytes(header[20..28].try_into().unwrap());
    
    // Parse Next Header CRC (4 bytes at offset 0x1C)
    let next_header_crc = Some(u32::from_le_bytes(header[28..32].try_into().unwrap()));
    
    // Calculate absolute offset: 0x20 (32) + relative offset
    let absolute_offset = 32 + next_offset_relative;
    
    // Check if headers are encrypted by reading first byte of Next Header
    let mut encrypted = false;
    if next_size > 0 {
        if file.seek(SeekFrom::Start(absolute_offset)).is_ok() {
            let mut next_header_byte = [0u8; 1];
            if file.read_exact(&mut next_header_byte).is_ok() {
                // 0x17 = EncodedHeader - metadata is compressed and/or encrypted
                if next_header_byte[0] == header_types::ENCODED_HEADER {
                    debug!(
                        path = %path,
                        "7z has EncodedHeader - metadata may be encrypted"
                    );
                    // Try to detect AES in the encoded header stream info
                    encrypted = detect_encryption(&mut file, absolute_offset).unwrap_or(false);
                }
            }
        }
    }
    
    debug!(
        path = %path,
        version = ?version,
        next_header_offset = absolute_offset,
        next_header_size = next_size,
        crc_valid = ?start_header_crc_valid,
        encrypted = encrypted,
        "7z metadata parsed"
    );
    
    Ok(SevenZipMetadata {
        next_header_offset: Some(absolute_offset),
        next_header_size: Some(next_size),
        version,
        start_header_crc_valid,
        next_header_crc,
        encrypted,
    })
}

/// Detect if 7z encoded header contains AES encryption
/// 
/// When Next Header starts with 0x17 (EncodedHeader), we need to parse
/// the StreamsInfo to check if AES codec is in the decode pipeline.
/// AES codec ID: 06 F1 07 01 (or variations)
fn detect_encryption(file: &mut File, next_header_offset: u64) -> Result<bool, String> {
    file.seek(SeekFrom::Start(next_header_offset))
        .map_err(|e| format!("Failed to seek to Next Header: {e}"))?;
    
    // Read first chunk of encoded header to look for AES codec markers
    let mut buf = [0u8; 256];
    let bytes_read = file.read(&mut buf).unwrap_or(0);
    
    if bytes_read == 0 {
        return Ok(false);
    }
    
    // Look for AES codec signature patterns in the encoded header
    // 7z AES codec IDs typically start with 06 F1 07
    for i in 0..bytes_read.saturating_sub(3) {
        if buf[i] == 0x06 && buf[i + 1] == 0xF1 && buf[i + 2] == 0x07 {
            return Ok(true);
        }
    }
    
    // Also check for 7zAES marker (alternative pattern)
    // 07 (codec ID length) followed by specific bytes
    for i in 0..bytes_read.saturating_sub(4) {
        if buf[i] == 0x07 && buf[i + 1] == 0x06 && buf[i + 2] == 0xF1 {
            return Ok(true);
        }
    }
    
    Ok(false)
}

// =============================================================================
// CRC32 Implementation (ISO 3309 polynomial)
// =============================================================================

/// CRC32 calculation for 7z (ISO 3309 polynomial, same as used in PNG/GZIP)
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for byte in data {
        let index = ((crc ^ (*byte as u32)) & 0xFF) as usize;
        crc = CRC32_TABLE[index] ^ (crc >> 8);
    }
    !crc
}

/// CRC32 lookup table (ISO 3309 polynomial: 0xEDB88320)
static CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = 0xEDB88320 ^ (crc >> 1);
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};
