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

use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use tracing::debug;

/// Archive format type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ArchiveFormat {
    SevenZip,
    Zip,
    Zip64,
    Rar4,
    Rar5,
    Gzip,
    Tar,
    TarGz,
}

impl std::fmt::Display for ArchiveFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveFormat::SevenZip => write!(f, "7-Zip"),
            ArchiveFormat::Zip => write!(f, "ZIP"),
            ArchiveFormat::Zip64 => write!(f, "ZIP64"),
            ArchiveFormat::Rar4 => write!(f, "RAR4"),
            ArchiveFormat::Rar5 => write!(f, "RAR5"),
            ArchiveFormat::Gzip => write!(f, "GZIP"),
            ArchiveFormat::Tar => write!(f, "TAR"),
            ArchiveFormat::TarGz => write!(f, "TAR.GZ"),
        }
    }
}

/// Archive information
#[derive(Debug, Clone, Serialize)]
pub struct ArchiveInfo {
    pub format: String,
    pub segment_count: u32,
    pub total_size: u64,
    pub segment_names: Vec<String>,
    pub segment_sizes: Vec<u64>,
    pub first_segment: String,
    pub last_segment: String,
    pub is_multipart: bool,
    /// Number of entries in the archive (from Central Directory for ZIP)
    pub entry_count: Option<u32>,
    /// Whether archive has encrypted headers (filenames hidden)
    pub encrypted_headers: bool,
    /// Whether archive uses AES encryption
    pub aes_encrypted: bool,
    /// ZIP-specific: Central Directory offset
    pub central_dir_offset: Option<u64>,
    /// ZIP-specific: Central Directory size
    pub central_dir_size: Option<u32>,
    /// 7z-specific: Next header offset (absolute, from file start)
    pub next_header_offset: Option<u64>,
    /// 7z-specific: Next header size
    pub next_header_size: Option<u64>,
    /// 7z-specific: Archive version (major.minor)
    pub version: Option<String>,
    /// 7z-specific: Start Header CRC valid
    pub start_header_crc_valid: Option<bool>,
    /// 7z-specific: Next Header CRC (for reference)
    pub next_header_crc: Option<u32>,
    /// Cellebrite extraction detected (UFDR/UFDX/UFD)
    pub cellebrite_detected: bool,
    /// Cellebrite file paths found inside archive
    pub cellebrite_files: Vec<String>,
}

// Magic bytes for various archive formats
// ZIP signatures
const ZIP_LOCAL_HEADER_SIG: &[u8] = &[0x50, 0x4B, 0x03, 0x04]; // PK\x03\x04
#[allow(dead_code)]
const ZIP_CENTRAL_DIR_SIG: &[u8] = &[0x50, 0x4B, 0x01, 0x02]; // PK\x01\x02
const ZIP_EOCD_SIG: &[u8] = &[0x50, 0x4B, 0x05, 0x06]; // PK\x05\x06
const ZIP64_EOCD_LOC_SIG: &[u8] = &[0x50, 0x4B, 0x06, 0x07]; // ZIP64 EOCD Locator
#[allow(dead_code)]
const ZIP64_EOCD_SIG: &[u8] = &[0x50, 0x4B, 0x06, 0x06]; // ZIP64 EOCD

// 7-Zip signature
const SEVEN_ZIP_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

// RAR signatures (distinguish RAR4 vs RAR5)
const RAR4_MAGIC: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]; // Rar!...
const RAR5_MAGIC: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]; // Rar!....

// Other formats
const GZIP_MAGIC: &[u8] = &[0x1F, 0x8B];
const TAR_MAGIC: &[u8] = b"ustar"; // TAR (at offset 257)

/// Check if a file is an archive format
pub fn is_archive(path: &str) -> Result<bool, String> {
    let lower = path.to_lowercase();
    
    // Quick extension check first
    if lower.ends_with(".7z") || lower.ends_with(".7z.001") 
        || lower.ends_with(".zip") || lower.ends_with(".zip.001")
        || lower.ends_with(".rar") || lower.ends_with(".r00") || lower.ends_with(".r01")
        || lower.ends_with(".gz") || lower.ends_with(".gzip")
        || lower.ends_with(".tar") || lower.ends_with(".tar.gz") || lower.ends_with(".tgz")
    {
        return Ok(true);
    }
    
    // Check for numbered 7z segments (.001, .002, etc. after .7z base)
    if is_7z_segment(&lower) {
        return Ok(true);
    }
    
    // Signature check for ambiguous extensions
    match detect_archive_format(path) {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(_) => Ok(false),
    }
}

/// Detect archive format from file signature
pub fn detect_archive_format(path: &str) -> Result<Option<ArchiveFormat>, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file: {e}"))?;
    
    let mut header = [0u8; 262];
    let bytes_read = file.read(&mut header)
        .map_err(|e| format!("Failed to read file header: {e}"))?;
    
    if bytes_read < 6 {
        return Ok(None);
    }
    
    // Check 7z signature (37 7A BC AF 27 1C)
    if bytes_read >= 6 && header[..6] == *SEVEN_ZIP_MAGIC {
        debug!("Detected 7-Zip format for: {}", path);
        return Ok(Some(ArchiveFormat::SevenZip));
    }
    
    // Check RAR5 first (longer signature) - 52 61 72 21 1A 07 01 00
    if bytes_read >= 8 && header[..8] == *RAR5_MAGIC {
        debug!("Detected RAR5 format for: {}", path);
        return Ok(Some(ArchiveFormat::Rar5));
    }
    
    // Check RAR4 - 52 61 72 21 1A 07 00
    if bytes_read >= 7 && header[..7] == *RAR4_MAGIC {
        debug!("Detected RAR4 format for: {}", path);
        return Ok(Some(ArchiveFormat::Rar4));
    }
    
    // Check ZIP signatures (PK..)
    if bytes_read >= 4 && (header[..4] == *ZIP_LOCAL_HEADER_SIG || header[..4] == *ZIP_EOCD_SIG) {
        // Check if ZIP64 by looking for ZIP64 EOCD
        if let Ok(is_zip64) = check_zip64(&mut file) {
            if is_zip64 {
                debug!("Detected ZIP64 format for: {}", path);
                return Ok(Some(ArchiveFormat::Zip64));
            }
        }
        debug!("Detected ZIP format for: {}", path);
        return Ok(Some(ArchiveFormat::Zip));
    }
    
    // Check GZIP signature (1F 8B)
    if bytes_read >= 2 && header[..2] == *GZIP_MAGIC {
        debug!("Detected GZIP format for: {}", path);
        return Ok(Some(ArchiveFormat::Gzip));
    }
    
    // Check TAR signature ("ustar" at offset 257)
    if bytes_read >= 262 {
        if &header[257..262] == TAR_MAGIC {
            debug!("Detected TAR format for: {}", path);
            return Ok(Some(ArchiveFormat::Tar));
        }
    }
    
    Ok(None)
}

/// Check if a ZIP file is ZIP64 format
fn check_zip64(file: &mut File) -> Result<bool, String> {
    let size = file.metadata()
        .map_err(|e| format!("Failed to get file size: {e}"))?
        .len();
    
    // Search backwards for ZIP64 EOCD Locator (PK\x06\x07)
    let search_size = size.min(65557 + 20) as usize; // EOCD max + ZIP64 locator
    let mut buf = vec![0u8; search_size];
    
    file.seek(SeekFrom::End(-(search_size as i64)))
        .map_err(|e| format!("Failed to seek: {e}"))?;
    file.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read: {e}"))?;
    
    // Look for ZIP64 EOCD Locator signature
    for i in (0..buf.len().saturating_sub(4)).rev() {
        if &buf[i..i + 4] == ZIP64_EOCD_LOC_SIG {
            return Ok(true);
        }
    }
    
    Ok(false)
}

/// Check if filename is a 7z numbered segment
fn is_7z_segment(lower: &str) -> bool {
    // Match patterns like: file.7z.001, file.7z.002, etc.
    if let Some(pos) = lower.rfind(".7z.") {
        let suffix = &lower[pos + 4..];
        return suffix.chars().all(|c| c.is_ascii_digit()) && !suffix.is_empty();
    }
    false
}

/// Get archive information including segment discovery
pub fn info(path: &str) -> Result<ArchiveInfo, String> {
    debug!(path = %path, "Getting archive info");
    
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("Archive file not found: {path}"));
    }
    
    let format = detect_archive_format(path)?
        .ok_or_else(|| format!("Unable to detect archive format: {path}"))?;
    
    let format_str = format.to_string();
    
    // Discover segments for multi-part archives
    let (segment_names, segment_sizes) = discover_segments(path, format)?;
    let segment_count = segment_names.len() as u32;
    let total_size: u64 = segment_sizes.iter().sum();
    
    let first_segment = segment_names.first().cloned().unwrap_or_default();
    let last_segment = segment_names.last().cloned().unwrap_or_default();
    let is_multipart = segment_count > 1;
    
    // Parse format-specific metadata
    let (entry_count, central_dir_offset, central_dir_size, mut encrypted_headers, aes_encrypted) = 
        match format {
            ArchiveFormat::Zip | ArchiveFormat::Zip64 => {
                parse_zip_metadata(path).unwrap_or((None, None, None, false, false))
            }
            _ => (None, None, None, false, false),
        };
    
    // Parse 7z-specific metadata with full Start Header details
    let (next_header_offset, next_header_size, version, start_header_crc_valid, next_header_crc, sevenz_encrypted) = 
        match format {
            ArchiveFormat::SevenZip => {
                parse_7z_metadata(path).unwrap_or((None, None, None, None, None, false))
            }
            _ => (None, None, None, None, None, false),
        };
    
    // Set encrypted_headers for 7z if detected
    if sevenz_encrypted {
        encrypted_headers = true;
    }
    
    // Detect Cellebrite UFDR/UFDX/UFD files inside the archive
    let (cellebrite_detected, cellebrite_files) = match format {
        ArchiveFormat::Zip | ArchiveFormat::Zip64 => {
            detect_cellebrite_in_zip(path).unwrap_or((false, vec![]))
        }
        _ => (false, vec![]),
    };
    
    debug!(
        path = %path,
        format = %format_str,
        segment_count = segment_count,
        total_size = total_size,
        entry_count = ?entry_count,
        cellebrite_detected = cellebrite_detected,
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
        cellebrite_detected,
        cellebrite_files,
    })
}

/// Parse ZIP End of Central Directory (EOCD) to get metadata
/// 
/// EOCD Layout (search backwards for PK\x05\x06):
/// | Offset | Size | Field              |
/// | 0x10   | 4    | Central Dir Offset |
/// | 0x0C   | 4    | Central Dir Size   |
/// | 0x0A   | 2    | Total Entries      |
fn parse_zip_metadata(path: &str) -> Result<(Option<u32>, Option<u64>, Option<u32>, bool, bool), String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open ZIP: {e}"))?;
    
    let size = file.metadata()
        .map_err(|e| format!("Failed to get file size: {e}"))?
        .len();
    
    // Search backwards for EOCD (max 65557 bytes from end)
    let search_size = size.min(65557) as usize;
    let mut buf = vec![0u8; search_size];
    
    file.seek(SeekFrom::End(-(search_size as i64)))
        .map_err(|e| format!("Failed to seek: {e}"))?;
    file.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read: {e}"))?;
    
    // Find EOCD signature (PK\x05\x06)
    let eocd_offset = (0..buf.len().saturating_sub(4))
        .rev()
        .find(|&i| &buf[i..i + 4] == ZIP_EOCD_SIG);
    
    let Some(eocd_pos) = eocd_offset else {
        return Ok((None, None, None, false, false));
    };
    
    // Parse EOCD fields
    // Offset 0x0A: Total entries (2 bytes)
    let entry_count = if eocd_pos + 12 <= buf.len() {
        Some(u16::from_le_bytes([buf[eocd_pos + 10], buf[eocd_pos + 11]]) as u32)
    } else {
        None
    };
    
    // Offset 0x0C: Central Directory Size (4 bytes)
    let cd_size = if eocd_pos + 16 <= buf.len() {
        Some(u32::from_le_bytes([
            buf[eocd_pos + 12],
            buf[eocd_pos + 13],
            buf[eocd_pos + 14],
            buf[eocd_pos + 15],
        ]))
    } else {
        None
    };
    
    // Offset 0x10: Central Directory Offset (4 bytes)
    let cd_offset = if eocd_pos + 20 <= buf.len() {
        let offset = u32::from_le_bytes([
            buf[eocd_pos + 16],
            buf[eocd_pos + 17],
            buf[eocd_pos + 18],
            buf[eocd_pos + 19],
        ]);
        // Check for ZIP64 marker (0xFFFFFFFF)
        if offset == 0xFFFFFFFF {
            None // Would need to parse ZIP64 EOCD
        } else {
            Some(offset as u64)
        }
    } else {
        None
    };
    
    // Check for AES encryption by scanning Central Directory for extra field 0x9901
    let aes_encrypted = if let (Some(offset), Some(size)) = (cd_offset, cd_size) {
        check_zip_aes(&mut file, offset, size).unwrap_or(false)
    } else {
        false
    };
    
    Ok((entry_count, cd_offset, cd_size, false, aes_encrypted))
}

/// Check if ZIP uses AES encryption (Extra Field Header ID 0x9901)
fn check_zip_aes(file: &mut File, cd_offset: u64, cd_size: u32) -> Result<bool, String> {
    file.seek(SeekFrom::Start(cd_offset))
        .map_err(|e| format!("Failed to seek to Central Directory: {e}"))?;
    
    let mut buf = vec![0u8; cd_size.min(4096) as usize];
    let bytes_read = file.read(&mut buf)
        .map_err(|e| format!("Failed to read Central Directory: {e}"))?;
    
    // Look for AES extra field header (0x9901)
    for i in 0..bytes_read.saturating_sub(2) {
        if buf[i] == 0x01 && buf[i + 1] == 0x99 {
            return Ok(true);
        }
    }
    
    Ok(false)
}

// =============================================================================
// Cellebrite UFDR/UFDX/UFD Detection
// =============================================================================

/// Cellebrite file extensions to detect
const CELLEBRITE_EXTENSIONS: &[&str] = &[".ufdr", ".ufdx", ".ufd"];

/// Check if a filename is a Cellebrite extraction file
fn is_cellebrite_file(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    CELLEBRITE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Detect Cellebrite UFDR/UFDX/UFD files inside a ZIP archive
/// Also checks for nested ZIPs that might contain Cellebrite files
/// 
/// Returns: (detected, list of cellebrite file paths found)
fn detect_cellebrite_in_zip(path: &str) -> Result<(bool, Vec<String>), String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open ZIP: {e}"))?;
    
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| format!("Failed to read ZIP archive: {e}"))?;
    
    let mut cellebrite_files: Vec<String> = Vec::new();
    let mut nested_zips: Vec<String> = Vec::new();
    
    // First pass: scan all entries in the archive
    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            let name = entry.name().to_string();
            let lower_name = name.to_lowercase();
            
            // Check for Cellebrite files
            if is_cellebrite_file(&lower_name) {
                debug!(path = %path, entry = %name, "Found Cellebrite file in ZIP");
                cellebrite_files.push(name.clone());
            }
            
            // Track nested ZIP files for deeper inspection
            if lower_name.ends_with(".zip") {
                nested_zips.push(name);
            }
        }
    }
    
    // Second pass: check inside nested ZIPs (one level deep)
    for nested_zip_name in &nested_zips {
        if let Ok(nested_files) = scan_nested_zip_for_cellebrite(&mut archive, nested_zip_name) {
            for nested_file in nested_files {
                let full_path = format!("{}/{}", nested_zip_name, nested_file);
                debug!(path = %path, entry = %full_path, "Found Cellebrite file in nested ZIP");
                cellebrite_files.push(full_path);
            }
        }
    }
    
    let detected = !cellebrite_files.is_empty();
    
    if detected {
        debug!(
            path = %path,
            count = cellebrite_files.len(),
            files = ?cellebrite_files,
            "Cellebrite files detected"
        );
    }
    
    Ok((detected, cellebrite_files))
}

/// Scan a nested ZIP inside the parent archive for Cellebrite files
fn scan_nested_zip_for_cellebrite(
    parent_archive: &mut zip::ZipArchive<File>,
    nested_zip_name: &str,
) -> Result<Vec<String>, String> {
    use std::io::{Cursor, Read};
    
    let mut cellebrite_files: Vec<String> = Vec::new();
    
    // Extract the nested ZIP to memory
    let nested_data = {
        let mut entry = parent_archive.by_name(nested_zip_name)
            .map_err(|e| format!("Failed to read nested ZIP {}: {e}", nested_zip_name))?;
        
        // Limit nested ZIP size to prevent memory issues (100MB max)
        let size = entry.size();
        if size > 100 * 1024 * 1024 {
            debug!(nested_zip = %nested_zip_name, size = size, "Nested ZIP too large, skipping");
            return Ok(vec![]);
        }
        
        let mut data = Vec::with_capacity(size as usize);
        entry.read_to_end(&mut data)
            .map_err(|e| format!("Failed to extract nested ZIP: {e}"))?;
        data
    };
    
    // Parse the nested ZIP
    let cursor = Cursor::new(nested_data);
    let mut nested_archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(e) => {
            debug!(nested_zip = %nested_zip_name, error = %e, "Failed to parse nested ZIP");
            return Ok(vec![]);
        }
    };
    
    // Scan nested archive entries
    for i in 0..nested_archive.len() {
        if let Ok(entry) = nested_archive.by_index(i) {
            let name = entry.name().to_string();
            if is_cellebrite_file(&name) {
                cellebrite_files.push(name);
            }
        }
    }
    
    Ok(cellebrite_files)
}

// =============================================================================
// 7-Zip Parsing (Based on 7Z_RECORD_LAYOUT spec)
// =============================================================================

/// 7z Header Type IDs (first byte of Next Header determines meaning)
#[allow(dead_code)]
mod sevenz_header_types {
    pub const END: u8 = 0x00;
    pub const HEADER: u8 = 0x01;
    pub const ARCHIVE_PROPERTIES: u8 = 0x02;
    pub const ADDITIONAL_STREAMS_INFO: u8 = 0x03;
    pub const MAIN_STREAMS_INFO: u8 = 0x04;
    pub const FILES_INFO: u8 = 0x05;
    pub const ENCODED_HEADER: u8 = 0x17;  // Indicates compressed/encrypted metadata
}

/// Parse 7-Zip Start Header and Next Header metadata
/// 
/// 7z Signature Header Layout (32 bytes total):
/// | Offset | Size | Field              | Notes                                |
/// |--------|------|--------------------|--------------------------------------|
/// | 0x00   | 6    | Signature          | 37 7A BC AF 27 1C                   |
/// | 0x06   | 2    | Version            | major (1 byte), minor (1 byte)      |
/// | 0x08   | 4    | Start Header CRC   | CRC32 of bytes 0x0C-0x1F            |
/// | 0x0C   | 8    | Next Header Offset | Relative to byte 0x20               |
/// | 0x14   | 8    | Next Header Size   |                                      |
/// | 0x1C   | 4    | Next Header CRC    |                                      |
/// 
/// Returns: (next_header_offset, next_header_size, version, start_header_crc_valid, next_header_crc, encrypted)
fn parse_7z_metadata(path: &str) -> Result<(Option<u64>, Option<u64>, Option<String>, Option<bool>, Option<u32>, bool), String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open 7z: {e}"))?;
    
    let mut header = [0u8; 32];
    file.read_exact(&mut header)
        .map_err(|e| format!("Failed to read 7z header: {e}"))?;
    
    // Verify signature (6 bytes at offset 0)
    if &header[..6] != SEVEN_ZIP_MAGIC {
        return Ok((None, None, None, None, None, false));
    }
    
    // Parse version (2 bytes at offset 6: major, minor)
    let version_major = header[6];
    let version_minor = header[7];
    let version = Some(format!("{}.{}", version_major, version_minor));
    
    // Parse Start Header CRC (4 bytes at offset 8)
    // This CRC covers bytes 0x0C to 0x1F (20 bytes: next header offset, size, and CRC)
    let stored_start_crc = u32::from_le_bytes(header[8..12].try_into().unwrap());
    let computed_start_crc = crc32_7z(&header[12..32]);
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
        if let Ok(_) = file.seek(SeekFrom::Start(absolute_offset)) {
            let mut next_header_byte = [0u8; 1];
            if file.read_exact(&mut next_header_byte).is_ok() {
                // 0x17 = EncodedHeader - metadata is compressed and/or encrypted
                // When encoded, we can't determine if it's encrypted without
                // parsing the full decode pipeline, so we mark it as potentially encrypted
                if next_header_byte[0] == sevenz_header_types::ENCODED_HEADER {
                    // EncodedHeader detected - need to check if encryption is in decode chain
                    // For now, we just note it's encoded (might be compressed only or encrypted)
                    debug!(
                        path = %path,
                        "7z has EncodedHeader - metadata may be encrypted"
                    );
                    // Try to detect AES in the encoded header stream info
                    encrypted = detect_7z_encryption(&mut file, absolute_offset).unwrap_or(false);
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
    
    Ok((
        Some(absolute_offset),
        Some(next_size),
        version,
        start_header_crc_valid,
        next_header_crc,
        encrypted,
    ))
}

/// Detect if 7z encoded header contains AES encryption
/// 
/// When Next Header starts with 0x17 (EncodedHeader), we need to parse
/// the StreamsInfo to check if AES codec is in the decode pipeline.
/// AES codec ID: 06 F1 07 01 (or variations)
fn detect_7z_encryption(file: &mut File, next_header_offset: u64) -> Result<bool, String> {
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

/// CRC32 calculation for 7z (ISO 3309 polynomial, same as used in PNG/GZIP)
fn crc32_7z(data: &[u8]) -> u32 {
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

/// Discover all segments of a multi-part archive
fn discover_segments(path: &str, format: ArchiveFormat) -> Result<(Vec<String>, Vec<u64>), String> {
    let path_obj = Path::new(path);
    let dir = path_obj.parent()
        .ok_or_else(|| "Cannot determine parent directory".to_string())?;
    let filename = path_obj.file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| "Invalid filename".to_string())?;
    
    let lower = filename.to_lowercase();
    
    // Get the base name for segment matching
    let (base_name, pattern_type) = get_segment_pattern(&lower, format);
    
    let mut segments: Vec<(String, u64, u32)> = Vec::new();
    
    // Read directory and find matching segments
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let entry_name = entry.file_name().to_string_lossy().to_string();
            let entry_lower = entry_name.to_lowercase();
            
            if let Some(seg_num) = match_segment(&entry_lower, &base_name, pattern_type) {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        let full_path = entry.path().to_string_lossy().to_string();
                        segments.push((full_path, meta.len(), seg_num));
                    }
                }
            }
        }
    }
    
    // Sort by segment number
    segments.sort_by_key(|(_, _, num)| *num);
    
    // If no segments found, just use the original file
    if segments.is_empty() {
        let size = std::fs::metadata(path)
            .map(|m| m.len())
            .unwrap_or(0);
        return Ok((vec![path.to_string()], vec![size]));
    }
    
    let names: Vec<String> = segments.iter().map(|(n, _, _)| n.clone()).collect();
    let sizes: Vec<u64> = segments.iter().map(|(_, s, _)| *s).collect();
    
    Ok((names, sizes))
}

#[derive(Clone, Copy)]
enum SegmentPatternType {
    // .7z.001, .7z.002, etc.
    DotNumeric,
    // .zip.001, .zip.002, etc. 
    ZipNumeric,
    // .r00, .r01, .rar
    RarStyle,
    // .z01, .z02, .zip
    ZipSplit,
    // Single file (no pattern)
    Single,
}

fn get_segment_pattern(lower: &str, format: ArchiveFormat) -> (String, SegmentPatternType) {
    match format {
        ArchiveFormat::SevenZip => {
            // Check for .7z.001 pattern
            if let Some(pos) = lower.rfind(".7z.") {
                let base = &lower[..pos + 3]; // Include .7z
                return (base.to_string(), SegmentPatternType::DotNumeric);
            }
            // Single .7z file
            if lower.ends_with(".7z") {
                return (lower[..lower.len() - 3].to_string(), SegmentPatternType::Single);
            }
        }
        ArchiveFormat::Zip => {
            // Check for .zip.001 pattern
            if let Some(pos) = lower.rfind(".zip.") {
                let base = &lower[..pos + 4]; // Include .zip
                return (base.to_string(), SegmentPatternType::ZipNumeric);
            }
            // Check for .z01, .z02 pattern (pkzip split)
            if lower.ends_with(".z01") || lower.ends_with(".z02") {
                let base = &lower[..lower.len() - 4];
                return (base.to_string(), SegmentPatternType::ZipSplit);
            }
            if lower.ends_with(".zip") {
                return (lower[..lower.len() - 4].to_string(), SegmentPatternType::Single);
            }
        }
        ArchiveFormat::Zip64 => {
            // Same patterns as ZIP
            if let Some(pos) = lower.rfind(".zip.") {
                let base = &lower[..pos + 4];
                return (base.to_string(), SegmentPatternType::ZipNumeric);
            }
            if lower.ends_with(".z01") || lower.ends_with(".z02") {
                let base = &lower[..lower.len() - 4];
                return (base.to_string(), SegmentPatternType::ZipSplit);
            }
            if lower.ends_with(".zip") {
                return (lower[..lower.len() - 4].to_string(), SegmentPatternType::Single);
            }
        }
        ArchiveFormat::Rar4 | ArchiveFormat::Rar5 => {
            // RAR segments: .rar, .r00, .r01, etc.
            if lower.ends_with(".rar") {
                return (lower[..lower.len() - 4].to_string(), SegmentPatternType::RarStyle);
            }
            if lower.len() > 4 && lower.chars().rev().take(3).all(|c| c.is_ascii_digit() || c == 'r' || c == '.') {
                // .r00, .r01, etc.
                let base = &lower[..lower.len() - 4];
                return (base.to_string(), SegmentPatternType::RarStyle);
            }
        }
        _ => {}
    }
    
    // Fallback: single file
    (lower.to_string(), SegmentPatternType::Single)
}

fn match_segment(entry_lower: &str, base_name: &str, pattern: SegmentPatternType) -> Option<u32> {
    match pattern {
        SegmentPatternType::DotNumeric => {
            // Match base.7z.NNN
            if entry_lower.starts_with(base_name) && entry_lower.len() > base_name.len() + 1 {
                let suffix = &entry_lower[base_name.len() + 1..]; // Skip the dot after .7z
                if suffix.chars().all(|c| c.is_ascii_digit()) {
                    return suffix.parse().ok();
                }
            }
            None
        }
        SegmentPatternType::ZipNumeric => {
            // Match base.zip.NNN
            if entry_lower.starts_with(base_name) && entry_lower.len() > base_name.len() + 1 {
                let suffix = &entry_lower[base_name.len() + 1..];
                if suffix.chars().all(|c| c.is_ascii_digit()) {
                    return suffix.parse().ok();
                }
            }
            None
        }
        SegmentPatternType::RarStyle => {
            // Match base.rar (segment 0) or base.rNN
            if entry_lower == format!("{}.rar", base_name) {
                return Some(0);
            }
            let prefix = format!("{}.", base_name);
            if entry_lower.starts_with(&prefix) {
                let ext = &entry_lower[prefix.len()..];
                if ext.starts_with('r') && ext.len() == 3 {
                    let num_part = &ext[1..];
                    if num_part.chars().all(|c| c.is_ascii_digit()) {
                        return num_part.parse::<u32>().ok().map(|n| n + 1);
                    }
                }
            }
            None
        }
        SegmentPatternType::ZipSplit => {
            // Match base.zip (last segment) or base.zNN
            if entry_lower == format!("{}.zip", base_name) {
                return Some(999); // ZIP file is always last in split archives
            }
            let prefix = format!("{}.", base_name);
            if entry_lower.starts_with(&prefix) {
                let ext = &entry_lower[prefix.len()..];
                if ext.starts_with('z') && ext.len() == 3 {
                    let num_part = &ext[1..];
                    if num_part.chars().all(|c| c.is_ascii_digit()) {
                        return num_part.parse().ok();
                    }
                }
            }
            None
        }
        SegmentPatternType::Single => {
            if entry_lower == base_name {
                return Some(1);
            }
            None
        }
    }
}

/// Check if a path is the first segment of a multi-part archive
pub fn is_first_segment(lower: &str) -> bool {
    // .7z.001 is first segment
    if lower.ends_with(".7z.001") {
        return true;
    }
    // .zip.001 is first segment
    if lower.ends_with(".zip.001") {
        return true;
    }
    // .r00 is first RAR segment (or .rar if no .r00 exists)
    if lower.ends_with(".r00") {
        return true;
    }
    // .z01 is first ZIP split segment
    if lower.ends_with(".z01") {
        return true;
    }
    // Single file archives
    if lower.ends_with(".7z") || lower.ends_with(".zip") || lower.ends_with(".rar") 
        || lower.ends_with(".tar") || lower.ends_with(".tar.gz") || lower.ends_with(".tgz")
        || lower.ends_with(".gz")
    {
        return true;
    }
    false
}

/// Check if a path is a non-first segment (should be hidden in scan)
pub fn is_continuation_segment(lower: &str) -> bool {
    // .7z.002, .7z.003, etc.
    if let Some(pos) = lower.rfind(".7z.") {
        let suffix = &lower[pos + 4..];
        if suffix.chars().all(|c| c.is_ascii_digit()) && suffix != "001" {
            return true;
        }
    }
    // .zip.002, .zip.003, etc.
    if let Some(pos) = lower.rfind(".zip.") {
        let suffix = &lower[pos + 5..];
        if suffix.chars().all(|c| c.is_ascii_digit()) && suffix != "001" {
            return true;
        }
    }
    // .r01, .r02, etc. (not .r00)
    if lower.len() >= 4 {
        let ext = &lower[lower.len() - 4..];
        if ext.starts_with(".r") && ext[2..].chars().all(|c| c.is_ascii_digit()) && ext != ".r00" {
            return true;
        }
    }
    // .z02, .z03, etc. (not .z01)
    if lower.len() >= 4 {
        let ext = &lower[lower.len() - 4..];
        if ext.starts_with(".z") && ext[2..].chars().all(|c| c.is_ascii_digit()) && ext != ".z01" {
            return true;
        }
    }
    false
}
