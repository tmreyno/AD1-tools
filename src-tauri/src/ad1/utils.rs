//! Utility functions for AD1 parsing

use std::path::Path;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::SystemTime;
use chrono::{Local, NaiveDateTime, TimeZone};
use filetime::FileTime;
use tracing::trace;

use super::types::*;
use crate::common::binary::{read_u32_at, read_u64_at, read_string_at};

/// Get segment files with their sizes and track missing segments
/// Returns (segment_names, segment_sizes, total_size, missing_segments)
pub fn get_segment_files_with_sizes(path: &str, segment_count: u32) -> (Vec<String>, Vec<u64>, u64, Vec<String>) {
    let path_obj = Path::new(path);
    let parent = path_obj.parent();
    let stem = path_obj.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    
    let mut segment_names = Vec::new();
    let mut segment_sizes = Vec::new();
    let mut missing_segments = Vec::new();
    let mut total_size = 0u64;
    
    for i in 1..=segment_count {
        let segment_name = format!("{}.ad{}", stem, i);
        if let Some(parent_dir) = parent {
            let segment_path = parent_dir.join(&segment_name);
            if segment_path.exists() {
                segment_names.push(segment_name);
                if let Ok(metadata) = std::fs::metadata(&segment_path) {
                    let size = metadata.len();
                    segment_sizes.push(size);
                    total_size += size;
                } else {
                    segment_sizes.push(0);
                }
            } else {
                missing_segments.push(segment_name);
            }
        }
    }
    
    (segment_names, segment_sizes, total_size, missing_segments)
}

/// Validate AD1 file format (does not check segments)
pub fn validate_format(path: &str) -> Result<(), String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("Input file not found: {path}"));
    }

    let mut file = File::open(path_obj)
        .map_err(|e| format!("Failed to open input file: {e}"))?;
    let mut signature = [0u8; 16];
    file.read_exact(&mut signature)
        .map_err(|e| format!("Failed to read file signature: {e}"))?;
    if &signature[..15] != AD1_SIGNATURE {
        return Err("File is not an AD1 segmented image".to_string());
    }

    let segment_count = read_u32_at(&mut file, 0x1c)?;
    if segment_count == 0 {
        return Err("Invalid AD1 segment count".to_string());
    }

    Ok(())
}

/// Validate AD1 file and check all segments exist (strict validation)
pub fn validate_input(path: &str) -> Result<(), String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("Input file not found: {path}"));
    }

    let mut file = File::open(path_obj)
        .map_err(|e| format!("Failed to open input file: {e}"))?;
    let mut signature = [0u8; 16];
    file.read_exact(&mut signature)
        .map_err(|e| format!("Failed to read file signature: {e}"))?;
    if &signature[..15] != AD1_SIGNATURE {
        return Err("File is not an AD1 segmented image".to_string());
    }

    let segment_count = read_u32_at(&mut file, 0x1c)?;
    if segment_count == 0 {
        return Err("Invalid AD1 segment count".to_string());
    }

    for index in 1..=segment_count {
        let segment_path = build_segment_path(path, index);
        if !Path::new(&segment_path).exists() {
            return Err(format!("Missing AD1 segment: {segment_path}"));
        }
    }

    Ok(())
}

/// Build segment file path from base path and segment index
pub fn build_segment_path(base: &str, index: u32) -> String {
    if base.is_empty() {
        return base.to_string();
    }
    let mut out = base.to_string();
    out.pop();
    out.push_str(&index.to_string());
    out
}

/// Read segment header from file
pub fn read_segment_header(file: &mut File) -> Result<SegmentHeader, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Failed to seek segment header: {e}"))?;
    let mut signature = [0u8; 16];
    file.read_exact(&mut signature)
        .map_err(|e| format!("Failed to read segment signature: {e}"))?;
    if &signature[..15] != AD1_SIGNATURE {
        return Err("File is not of AD1 format".to_string());
    }

    Ok(SegmentHeader {
        signature,
        segment_index: read_u32_at(file, 0x18)?,
        segment_number: read_u32_at(file, 0x1c)?,
        fragments_size: read_u32_at(file, 0x22)?,
        header_size: read_u32_at(file, 0x28)?,
    })
}

/// Read logical header from file
pub fn read_logical_header(file: &mut File) -> Result<LogicalHeader, String> {
    let signature = read_string_at(file, AD1_LOGICAL_MARGIN, 15)?;
    let image_version = read_u32_at(file, 0x210)?;
    let zlib_chunk_size = read_u32_at(file, 0x218)?;
    let logical_metadata_addr = read_u64_at(file, 0x21c)?;
    let first_item_addr = read_u64_at(file, 0x224)?;
    let data_source_name_length = read_u32_at(file, 0x22c)?;
    let ad_signature = read_string_at(file, 0x230, 3)?;
    let data_source_name_addr = read_u64_at(file, 0x234)?;
    let attrguid_footer_addr = read_u64_at(file, 0x23c)?;
    let locsguid_footer_addr = read_u64_at(file, 0x24c)?;
    let data_source_name = read_string_at(file, 0x25c, data_source_name_length as usize)?;

    Ok(LogicalHeader {
        signature: copy_into_array(&signature, 16)?,
        image_version,
        zlib_chunk_size,
        logical_metadata_addr,
        first_item_addr,
        data_source_name_length,
        ad_signature: copy_into_array(&ad_signature, 4)?,
        data_source_name_addr,
        attrguid_footer_addr,
        locsguid_footer_addr,
        data_source_name,
    })
}

/// Copy string into fixed-size byte array
pub fn copy_into_array<const N: usize>(value: &str, max_len: usize) -> Result<[u8; N], String> {
    let mut buf = [0u8; N];
    let bytes = value.as_bytes();
    let len = bytes.len().min(max_len).min(N);
    buf[..len].copy_from_slice(&bytes[..len]);
    Ok(buf)
}

/// Calculate segment span from fragments size
pub fn segment_span(fragments_size: u32) -> u64 {
    (fragments_size as u64 * SEGMENT_BLOCK_SIZE).saturating_sub(AD1_LOGICAL_MARGIN)
}

/// Convert bytes to string (stops at null terminator)
pub fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

/// Convert metadata bytes to string (trimmed)
pub fn metadata_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

/// Join path components
pub fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else if name.is_empty() {
        parent.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

/// Convert SegmentHeader to public SegmentHeaderInfo
pub fn segment_header_info(header: &SegmentHeader) -> SegmentHeaderInfo {
    SegmentHeaderInfo {
        signature: bytes_to_string(&header.signature),
        segment_index: header.segment_index,
        segment_number: header.segment_number,
        fragments_size: header.fragments_size,
        header_size: header.header_size,
    }
}

/// Convert LogicalHeader to public LogicalHeaderInfo  
pub fn logical_header_info(header: &LogicalHeader) -> LogicalHeaderInfo {
    LogicalHeaderInfo {
        signature: bytes_to_string(&header.signature),
        image_version: header.image_version,
        zlib_chunk_size: header.zlib_chunk_size,
        logical_metadata_addr: header.logical_metadata_addr,
        first_item_addr: header.first_item_addr,
        data_source_name_length: header.data_source_name_length,
        ad_signature: bytes_to_string(&header.ad_signature),
        data_source_name_addr: header.data_source_name_addr,
        attrguid_footer_addr: header.attrguid_footer_addr,
        locsguid_footer_addr: header.locsguid_footer_addr,
        data_source_name: header.data_source_name.clone(),
    }
}

/// Apply metadata timestamps to extracted file
pub fn apply_metadata(path: &Path, metadata: &[Metadata]) -> Result<(), String> {
    let mut access_time = None;
    let mut modified_time = None;

    for meta in metadata {
        if meta.category != TIMESTAMP {
            continue;
        }
        let value = metadata_string(&meta.data);
        match meta.key {
            ACCESS => access_time = parse_timestamp(&value),
            MODIFIED => modified_time = parse_timestamp(&value),
            _ => {}
        }
    }

    if access_time.is_none() && modified_time.is_none() {
        return Ok(());
    }

    let now = FileTime::from_system_time(SystemTime::now());
    let atime = access_time.unwrap_or(now);
    let mtime = modified_time.unwrap_or(atime);
    filetime::set_file_times(path, atime, mtime)
        .map_err(|e| format!("Failed to set file times for {:?}: {e}", path))?;
    Ok(())
}

/// Parse AD1 timestamp string to FileTime
pub fn parse_timestamp(value: &str) -> Option<FileTime> {
    let trimmed = value.trim_matches('\0').trim();
    if trimmed.len() < 15 {
        return None;
    }
    let parsed = NaiveDateTime::parse_from_str(trimmed, "%Y%m%dT%H%M%S").ok()?;
    let local = Local
        .from_local_datetime(&parsed)
        .single()
        .unwrap_or_else(|| Local.from_utc_datetime(&parsed));
    Some(FileTime::from_unix_time(local.timestamp(), 0))
}

/// Find hash value in metadata
pub fn find_hash(metadata: &[Metadata], key: u32) -> Option<String> {
    // Debug: log all hash-related metadata entries
    for meta in metadata {
        if meta.category == HASH_INFO {
            let value = metadata_string(&meta.data);
            trace!(
                category = meta.category,
                key = format!("0x{:04x}", meta.key),
                expected_key = format!("0x{:04x}", key),
                value = %value,
                "Found hash metadata entry"
            );
        }
    }
    
    metadata
        .iter()
        .find(|meta| meta.category == HASH_INFO && meta.key == key)
        .map(|meta| metadata_string(&meta.data))
        .map(|value| {
            // Clean up the hash value - remove any whitespace or non-hex characters
            let cleaned: String = value.chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect();
            cleaned.to_lowercase()
        })
}

/// Collect tree entries recursively
pub fn collect_tree(items: &[Item], parent_path: &str, out: &mut Vec<TreeEntry>) {
    for item in items {
        let path = join_path(parent_path, &item.name);
        let is_dir = item.item_type == AD1_FOLDER_SIGNATURE;
        let size = if is_dir { 0 } else { item.decompressed_size };
        out.push(TreeEntry {
            path: path.clone(),
            is_dir,
            size,
            item_type: item.item_type,
        });
        collect_tree(&item.children, &path, out);
    }
}

/// Count total files (non-folders) in item tree
pub fn count_files(items: &[Item]) -> usize {
    items.iter().map(|item| {
        let self_count = if item.item_type != AD1_FOLDER_SIGNATURE { 1 } else { 0 };
        self_count + count_files(&item.children)
    }).sum()
}

/// Parse volume info from AD1 header region
pub fn parse_volume_info(file: &mut File) -> Option<VolumeInfo> {
    // Volume info is typically at offset 0x2A0+ in the logical header
    // Format: "C:\:NONAME [NTFS]" followed by OS info like "Windows XP (NTFS 3.1)"
    
    let mut info = VolumeInfo::default();
    
    // Read volume label region (around 0x2A0-0x2C0)
    if let Ok(volume_str) = read_string_at(file, 0x2A8, 64) {
        let volume_trimmed = volume_str.trim_matches(char::from(0)).trim();
        if !volume_trimmed.is_empty() && volume_trimmed.contains(':') {
            // Parse "C:\:NONAME [NTFS]" format
            if let Some(bracket_start) = volume_trimmed.find('[') {
                if let Some(bracket_end) = volume_trimmed.find(']') {
                    info.filesystem = Some(volume_trimmed[bracket_start+1..bracket_end].to_string());
                }
                info.volume_label = Some(volume_trimmed[..bracket_start].trim().to_string());
            } else {
                info.volume_label = Some(volume_trimmed.to_string());
            }
        }
    }
    
    // Read OS info region (around 0x370-0x3A0)
    if let Ok(os_str) = read_string_at(file, 0x370, 64) {
        let os_trimmed = os_str.trim_matches(char::from(0)).trim();
        if !os_trimmed.is_empty() && (os_trimmed.contains("Windows") || os_trimmed.contains("NTFS") || os_trimmed.contains("Linux")) {
            info.os_info = Some(os_trimmed.to_string());
        }
    }
    
    // Read block size (typically at 0x2E8)
    if let Ok(block_size_str) = read_string_at(file, 0x2E8, 8) {
        let block_trimmed = block_size_str.trim_matches(char::from(0)).trim();
        if let Ok(block_size) = block_trimmed.parse::<u32>() {
            if block_size > 0 && block_size <= 65536 {
                info.block_size = Some(block_size);
            }
        }
    }
    
    // Only return if we found something useful
    if info.volume_label.is_some() || info.filesystem.is_some() || info.os_info.is_some() {
        Some(info)
    } else {
        None
    }
}

/// Parse companion log file (.ad1.txt) for case metadata
pub fn parse_companion_log(ad1_path: &str) -> Option<CompanionLogInfo> {
    use std::io::BufRead;
    
    // Try common companion file patterns
    let txt_path = format!("{}.txt", ad1_path);
    let log_path = ad1_path.replace(".ad1", ".ad1.txt");
    
    let companion_path = if Path::new(&txt_path).exists() {
        txt_path
    } else if Path::new(&log_path).exists() {
        log_path
    } else {
        return None;
    };
    
    let file = match File::open(&companion_path) {
        Ok(f) => f,
        Err(_) => return None,
    };
    
    let reader = std::io::BufReader::new(file);
    let mut info = CompanionLogInfo::default();
    let mut notes_lines: Vec<String> = Vec::new();
    let mut in_notes = false;
    
    for line in reader.lines().map_while(Result::ok) {
        let line_lower = line.to_lowercase();
        
        // Parse key-value pairs
        if line.contains(':') && !in_notes {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                let key = parts[0].trim().to_lowercase();
                let value = parts[1].trim().to_string();
                
                if !value.is_empty() {
                    match key.as_str() {
                        "case number" | "case" | "case #" | "case no" => {
                            info.case_number = Some(value);
                        }
                        "evidence number" | "evidence" | "evidence #" | "evidence no" => {
                            info.evidence_number = Some(value);
                        }
                        "examiner name" | "examiner" => {
                            info.examiner = Some(value);
                        }
                        "md5" | "md5 hash" | "md5 checksum" => {
                            info.md5_hash = Some(value);
                        }
                        "sha1" | "sha1 hash" | "sha-1" | "sha1 checksum" => {
                            info.sha1_hash = Some(value);
                        }
                        "acquisition date" | "acquired" | "date" => {
                            info.acquisition_date = Some(value);
                        }
                        "notes" => {
                            if !value.is_empty() {
                                notes_lines.push(value);
                            }
                            in_notes = true;
                        }
                        _ => {}
                    }
                }
            }
        } else if in_notes {
            // Collect multi-line notes until we hit another key
            if line.contains(':') && !line.starts_with(' ') && !line.starts_with('\t') {
                in_notes = false;
            } else if !line.trim().is_empty() {
                notes_lines.push(line.trim().to_string());
            }
        }
        
        // Also look for hash values without colon format
        if line_lower.starts_with("md5") && info.md5_hash.is_none() {
            if let Some(hash) = extract_hash(&line, 32) {
                info.md5_hash = Some(hash);
            }
        }
        if (line_lower.starts_with("sha1") || line_lower.starts_with("sha-1")) && info.sha1_hash.is_none() {
            if let Some(hash) = extract_hash(&line, 40) {
                info.sha1_hash = Some(hash);
            }
        }
    }
    
    if !notes_lines.is_empty() {
        info.notes = Some(notes_lines.join("\n"));
    }
    
    // Only return if we found useful metadata
    if info.case_number.is_some() || info.evidence_number.is_some() || 
       info.examiner.is_some() || info.md5_hash.is_some() || info.sha1_hash.is_some() {
        Some(info)
    } else {
        None
    }
}

/// Extract hex hash from a line
fn extract_hash(line: &str, expected_len: usize) -> Option<String> {
    // Find hex string of expected length
    let hex_chars: String = line.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    
    if hex_chars.len() >= expected_len {
        Some(hex_chars[..expected_len].to_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_segment_path() {
        assert_eq!(build_segment_path("/path/to/file.ad1", 1), "/path/to/file.ad1");
        assert_eq!(build_segment_path("/path/to/file.ad1", 2), "/path/to/file.ad2");
        assert_eq!(build_segment_path("/path/to/file.ad1", 3), "/path/to/file.ad3");
        assert_eq!(build_segment_path("/path/to/file.ad1", 10), "/path/to/file.ad10");
        assert_eq!(build_segment_path("", 1), "");
    }

    #[test]
    fn test_join_path() {
        assert_eq!(join_path("", "file.txt"), "file.txt");
        assert_eq!(join_path("folder", ""), "folder");
        assert_eq!(join_path("folder", "file.txt"), "folder/file.txt");
        assert_eq!(join_path("a/b", "c.txt"), "a/b/c.txt");
    }

    #[test]
    fn test_segment_span() {
        assert_eq!(segment_span(0x10000), SEGMENT_BLOCK_SIZE * 0x10000 - AD1_LOGICAL_MARGIN);
        assert_eq!(segment_span(1), SEGMENT_BLOCK_SIZE - AD1_LOGICAL_MARGIN);
        assert_eq!(segment_span(0), 0);
    }

    #[test]
    fn test_copy_into_array() {
        let result: [u8; 4] = copy_into_array("test", 4).unwrap();
        assert_eq!(&result, b"test");

        let result: [u8; 8] = copy_into_array("hi", 8).unwrap();
        assert_eq!(&result[..2], b"hi");
        assert_eq!(&result[2..], &[0, 0, 0, 0, 0, 0]);
    }
}
