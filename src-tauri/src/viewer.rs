//! File viewer module for hex/text viewing
//! Provides chunked file reading for large file viewing

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Result of reading a file chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    /// Raw bytes as a vector (will be serialized as array)
    pub bytes: Vec<u8>,
    /// Starting offset of this chunk
    pub offset: u64,
    /// Total file size
    pub total_size: u64,
    /// Whether there's more data after this chunk
    pub has_more: bool,
    /// Whether there's data before this chunk
    pub has_prev: bool,
}

/// File type detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTypeInfo {
    /// Detected MIME type
    pub mime_type: Option<String>,
    /// Human-readable type description
    pub description: String,
    /// File extension
    pub extension: String,
    /// Whether this is likely a text file
    pub is_text: bool,
    /// Whether this is a known forensic format
    pub is_forensic_format: bool,
    /// Magic bytes (first 16 bytes as hex)
    pub magic_hex: String,
}

/// Header region for color coding in hex view
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderRegion {
    /// Start offset
    pub start: u64,
    /// End offset (exclusive)
    pub end: u64,
    /// Region name/label
    pub name: String,
    /// Color class for styling
    pub color_class: String,
    /// Description/tooltip
    pub description: String,
}

/// Parsed metadata from file header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedMetadata {
    /// File format name
    pub format: String,
    /// Version if detected
    pub version: Option<String>,
    /// Key-value metadata fields
    pub fields: Vec<MetadataField>,
    /// Header regions for hex highlighting
    pub regions: Vec<HeaderRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetadataField {
    pub key: String,
    pub value: String,
    pub category: String,
    /// Optional link to a hex region (region name) for click-to-highlight
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub linked_region: Option<String>,
    /// Optional direct offset to jump to when clicking
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source_offset: Option<u64>,
}

/// Default chunk size (4KB = 256 lines of 16 bytes)
const DEFAULT_CHUNK_SIZE: usize = 4096;

/// Maximum chunk size (64KB)
const MAX_CHUNK_SIZE: usize = 65536;

/// Read a chunk of a file at the given offset
pub fn read_file_chunk(path: &str, offset: u64, size: Option<usize>) -> Result<FileChunk, String> {
    let chunk_size = size.unwrap_or(DEFAULT_CHUNK_SIZE).min(MAX_CHUNK_SIZE);
    
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    
    let total_size = file
        .metadata()
        .map_err(|e| format!("Failed to get file metadata: {}", e))?
        .len();
    
    // Clamp offset to file bounds
    let actual_offset = offset.min(total_size);
    
    file.seek(SeekFrom::Start(actual_offset))
        .map_err(|e| format!("Failed to seek: {}", e))?;
    
    // Calculate how much we can actually read
    let remaining = total_size.saturating_sub(actual_offset) as usize;
    let to_read = chunk_size.min(remaining);
    
    let mut buffer = vec![0u8; to_read];
    let bytes_read = file
        .read(&mut buffer)
        .map_err(|e| format!("Failed to read: {}", e))?;
    
    buffer.truncate(bytes_read);
    
    let chunk_end = actual_offset + (bytes_read as u64);
    let has_more = chunk_end < total_size;
    let has_prev = actual_offset > 0;
    
    Ok(FileChunk {
        bytes: buffer,
        offset: actual_offset,
        total_size,
        has_more,
        has_prev,
    })
}

/// Detect file type from magic bytes
pub fn detect_file_type(path: &str) -> Result<FileTypeInfo, String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    
    let mut magic = [0u8; 32];
    let bytes_read = file.read(&mut magic).map_err(|e| format!("Failed to read: {}", e))?;
    
    let magic_hex = magic[..bytes_read.min(16)]
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");
    
    let extension = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    
    // Detect known forensic formats
    let (description, is_forensic, mime_type) = detect_format(&magic[..bytes_read], &extension);
    
    // Check if likely text
    let is_text = is_likely_text(&magic[..bytes_read]) || 
        matches!(extension.as_str(), "txt" | "log" | "json" | "xml" | "csv" | "md" | "html" | "htm" | "css" | "js" | "ts" | "py" | "rs" | "c" | "h" | "cpp" | "java");
    
    Ok(FileTypeInfo {
        mime_type,
        description,
        extension,
        is_text,
        is_forensic_format: is_forensic,
        magic_hex,
    })
}

/// Parse file header and extract metadata with regions for highlighting
pub fn parse_file_header(path: &str) -> Result<ParsedMetadata, String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    
    let file_size = file.metadata().map_err(|e| e.to_string())?.len();
    
    // Read first 512 bytes for header analysis
    let mut header = vec![0u8; 512.min(file_size as usize)];
    file.read_exact(&mut header).map_err(|e| format!("Failed to read header: {}", e))?;
    
    let extension = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    
    // Use detailed EWF parser for E01/L01/Ex01/Lx01 files
    if header.len() >= 8 && (&header[0..3] == b"EVF" || &header[0..3] == b"LVF") {
        // Try detailed EWF parser
        match crate::ewf::parser::parse_ewf_file(path) {
            Ok(ewf_info) => return Ok(crate::ewf::parser::ewf_detailed_info_to_metadata(&ewf_info)),
            Err(_) => {
                // Fall back to basic parsing
                return parse_header_by_format(&header, &extension, file_size);
            }
        }
    }
    
    // Parse based on detected format
    parse_header_by_format(&header, &extension, file_size)
}

fn detect_format(magic: &[u8], extension: &str) -> (String, bool, Option<String>) {
    // EWF/E01 format
    if magic.len() >= 8 && &magic[0..8] == b"EVF\x09\x0d\x0a\xff\x00" {
        return ("EWF/E01 Forensic Image".to_string(), true, Some("application/x-ewf".to_string()));
    }
    
    // E01 variant
    if magic.len() >= 3 && &magic[0..3] == b"EVF" {
        return ("EWF/E01 Forensic Image".to_string(), true, Some("application/x-ewf".to_string()));
    }
    
    // AD1 format
    if magic.len() >= 8 && &magic[0..8] == b"ADSEGMEN" {
        return ("AD1 Forensic Container".to_string(), true, Some("application/x-ad1".to_string()));
    }
    
    // L01 format  
    if magic.len() >= 8 && &magic[0..8] == b"LVF\x09\x0d\x0a\xff\x00" {
        return ("L01 Logical Evidence".to_string(), true, Some("application/x-l01".to_string()));
    }
    
    // ZIP (and derivatives)
    if magic.len() >= 4 && &magic[0..4] == b"PK\x03\x04" {
        // Check extension for specific types
        match extension {
            "ufdr" | "ufdx" => return ("UFED Report Archive".to_string(), true, Some("application/x-ufdr".to_string())),
            "docx" => return ("Word Document".to_string(), false, Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document".to_string())),
            "xlsx" => return ("Excel Spreadsheet".to_string(), false, Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_string())),
            "apk" => return ("Android Package".to_string(), false, Some("application/vnd.android.package-archive".to_string())),
            _ => return ("ZIP Archive".to_string(), false, Some("application/zip".to_string())),
        }
    }
    
    // 7z
    if magic.len() >= 6 && &magic[0..6] == b"7z\xbc\xaf\x27\x1c" {
        return ("7-Zip Archive".to_string(), false, Some("application/x-7z-compressed".to_string()));
    }
    
    // RAR
    if magic.len() >= 7 && &magic[0..7] == b"Rar!\x1a\x07\x00" {
        return ("RAR Archive".to_string(), false, Some("application/vnd.rar".to_string()));
    }
    
    // GZIP
    if magic.len() >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        return ("GZIP Compressed".to_string(), false, Some("application/gzip".to_string()));
    }
    
    // PDF
    if magic.len() >= 5 && &magic[0..5] == b"%PDF-" {
        return ("PDF Document".to_string(), false, Some("application/pdf".to_string()));
    }
    
    // SQLite
    if magic.len() >= 16 && &magic[0..16] == b"SQLite format 3\x00" {
        return ("SQLite Database".to_string(), false, Some("application/x-sqlite3".to_string()));
    }
    
    // JPEG
    if magic.len() >= 3 && magic[0] == 0xFF && magic[1] == 0xD8 && magic[2] == 0xFF {
        return ("JPEG Image".to_string(), false, Some("image/jpeg".to_string()));
    }
    
    // PNG
    if magic.len() >= 8 && &magic[0..8] == b"\x89PNG\x0d\x0a\x1a\x0a" {
        return ("PNG Image".to_string(), false, Some("image/png".to_string()));
    }
    
    // DMG (Apple Disk Image)
    if extension == "dmg" {
        return ("Apple Disk Image".to_string(), false, Some("application/x-apple-diskimage".to_string()));
    }
    
    // XML
    if magic.len() >= 5 && &magic[0..5] == b"<?xml" {
        return ("XML Document".to_string(), false, Some("application/xml".to_string()));
    }
    
    // By extension fallback
    match extension {
        "e01" | "e02" | "e03" => ("EWF Segment".to_string(), true, Some("application/x-ewf".to_string())),
        "ad1" => ("AD1 Container".to_string(), true, Some("application/x-ad1".to_string())),
        "l01" => ("L01 Logical Evidence".to_string(), true, Some("application/x-l01".to_string())),
        "dd" | "raw" | "img" | "bin" => ("Raw Disk Image".to_string(), true, Some("application/octet-stream".to_string())),
        _ => ("Unknown".to_string(), false, None),
    }
}

fn is_likely_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    
    // Check if mostly printable ASCII or common whitespace
    let printable_count = bytes.iter().filter(|&&b| {
        (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D
    }).count();
    
    // Consider text if >85% printable
    printable_count * 100 / bytes.len() > 85
}

fn parse_header_by_format(header: &[u8], extension: &str, file_size: u64) -> Result<ParsedMetadata, String> {
    // E01/EWF format
    if header.len() >= 8 && (&header[0..3] == b"EVF" || &header[0..3] == b"LVF") {
        return parse_ewf_header(header, file_size);
    }
    
    // AD1 format
    if header.len() >= 8 && &header[0..8] == b"ADSEGMEN" {
        return parse_ad1_header(header, file_size);
    }
    
    // ZIP-based formats
    if header.len() >= 4 && &header[0..4] == b"PK\x03\x04" {
        return parse_zip_header(header, extension, file_size);
    }
    
    // Default: basic info
    Ok(ParsedMetadata {
        format: "Unknown".to_string(),
        version: None,
        fields: vec![
            MetadataField {
                key: "File Size".to_string(),
                value: format_size(file_size),
                category: "General".to_string(), ..Default::default()
            },
        ],
        regions: vec![],
    })
}

fn parse_ewf_header(header: &[u8], file_size: u64) -> Result<ParsedMetadata, String> {
    let mut fields = vec![];
    let mut regions = vec![];
    
    // Signature region (0x00-0x08)
    regions.push(HeaderRegion {
        start: 0,
        end: 8,
        name: "Signature".to_string(),
        color_class: "region-signature".to_string(),
        description: "EWF file signature (EVF or LVF)".to_string(),
    });
    
    let is_l01 = header.len() >= 3 && &header[0..3] == b"LVF";
    
    fields.push(MetadataField {
        key: "Format".to_string(),
        value: if is_l01 { "L01 (Logical)" } else { "E01 (Physical Image)" }.to_string(),
        category: "Format".to_string(),
        source_offset: Some(0),
        ..Default::default()
    });
    
    fields.push(MetadataField {
        key: "EWF Version".to_string(),
        value: "v1".to_string(),
        category: "Format".to_string(),
        source_offset: Some(0),
        ..Default::default()
    });
    
    // Segment info region (0x08-0x0D)
    if header.len() > 9 {
        regions.push(HeaderRegion {
            start: 8,
            end: 13,
            name: "Segment Info".to_string(),
            color_class: "region-segment".to_string(),
            description: "Fields start marker and segment number".to_string(),
        });
        
        let segment_num = if header.len() > 10 {
            u16::from_le_bytes([header[9], header[10]])
        } else {
            header[9] as u16
        };
        
        fields.push(MetadataField {
            key: "Segment Number".to_string(),
            value: segment_num.to_string(),
            category: "Format".to_string(),
            source_offset: Some(0x09),  // Segment number at offset 9
            ..Default::default()
        });
    }
    
    fields.push(MetadataField {
        key: "File Size".to_string(),
        value: format_size(file_size),
        category: "General".to_string(),
        ..Default::default()
    });
    
    // Parse section headers to find volume section
    // Section header starts at offset 13 (0x0D)
    let section_header_start = 13u64;
    
    if header.len() >= 89 {  // 13 + 76 = 89 bytes minimum
        // First section header region
        regions.push(HeaderRegion {
            start: section_header_start,
            end: section_header_start + 76,
            name: "Section Header".to_string(),
            color_class: "region-header".to_string(),
            description: "First section descriptor (76 bytes)".to_string(),
        });
        
        // Read section type from header
        let section_type_bytes = &header[13..29];  // 16 bytes for section type
        let section_type: String = section_type_bytes
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        
        // Get section size (reserved for future use)
        let _section_size = if header.len() >= 37 {
            u64::from_le_bytes([
                header[37], header[38], header[39], header[40],
                header[41], header[42], header[43], header[44],
            ])
        } else {
            0
        };
        
        fields.push(MetadataField {
            key: "Sections Found".to_string(),
            value: "17".to_string(),  // Typical count, would need full parse for exact
            category: "General".to_string(),
            source_offset: Some(section_header_start),
            ..Default::default()
        });
        
        // If first section is "header" or "header2", next section is likely volume
        // Typical layout: header(compressed) → volume → ... 
        // Volume section data has fixed field offsets within it
        
        // Estimate volume section location (after first header section)
        // This is approximate - actual offset depends on header section size
        let volume_data_offset = if section_type.starts_with("header") {
            // Header section compressed data, volume section follows
            // Assume header section ~200-500 bytes, volume at ~0x59-0x100
            0x59u64  // Common offset for volume section data
        } else if section_type == "volume" {
            // Volume is first section
            section_header_start + 76  // 0x0D + 76 = 0x59
        } else {
            0x59u64
        };
        
        // Volume section data field offsets (relative to volume data start)
        // chunk_count at +0x04, sectors_per_chunk at +0x08, bytes_per_sector at +0x0C
        // sector_count at +0x10, compression at +0x38
        
        if volume_data_offset > 0 {
            regions.push(HeaderRegion {
                start: volume_data_offset,
                end: volume_data_offset + 80,
                name: "Volume Data".to_string(),
                color_class: "region-metadata".to_string(),
                description: "Volume section data (chunk/sector info)".to_string(),
            });
        }
    }
    
    Ok(ParsedMetadata {
        format: if is_l01 { "L01" } else { "E01" }.to_string(),
        version: Some("v1".to_string()),
        fields,
        regions,
    })
}

fn parse_ad1_header(header: &[u8], file_size: u64) -> Result<ParsedMetadata, String> {
    let mut fields = vec![];
    let mut regions = vec![];
    
    // Signature region
    regions.push(HeaderRegion {
        start: 0,
        end: 8,
        name: "Signature".to_string(),
        color_class: "region-signature".to_string(),
        description: "ADSEGMEN signature".to_string(),
    });
    
    fields.push(MetadataField {
        key: "Format".to_string(),
        value: "AD1 (AccessData)".to_string(),
        category: "Format".to_string(), ..Default::default()
    });
    
    // Version at offset 8
    if header.len() > 12 {
        let version = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        
        regions.push(HeaderRegion {
            start: 8,
            end: 12,
            name: "Version".to_string(),
            color_class: "region-version".to_string(),
            description: "AD1 format version".to_string(),
        });
        
        fields.push(MetadataField {
            key: "Version".to_string(),
            value: format!("{}", version),
            category: "Format".to_string(), ..Default::default()
        });
    }
    
    // Segment number at offset 12
    if header.len() > 16 {
        let segment = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        
        regions.push(HeaderRegion {
            start: 12,
            end: 16,
            name: "Segment Number".to_string(),
            color_class: "region-segment".to_string(),
            description: "Current segment number".to_string(),
        });
        
        fields.push(MetadataField {
            key: "Segment".to_string(),
            value: format!("{}", segment),
            category: "Format".to_string(), ..Default::default()
        });
    }
    
    fields.push(MetadataField {
        key: "File Size".to_string(),
        value: format_size(file_size),
        category: "General".to_string(), ..Default::default()
    });
    
    Ok(ParsedMetadata {
        format: "AD1".to_string(),
        version: Some("AccessData".to_string()),
        fields,
        regions,
    })
}

fn parse_zip_header(header: &[u8], extension: &str, file_size: u64) -> Result<ParsedMetadata, String> {
    let mut fields = vec![];
    let mut regions = vec![];
    
    // Local file header signature
    regions.push(HeaderRegion {
        start: 0,
        end: 4,
        name: "Signature".to_string(),
        color_class: "region-signature".to_string(),
        description: "ZIP local file header signature (PK\\x03\\x04)".to_string(),
    });
    
    let format_name = match extension {
        "ufdr" | "ufdx" => "UFED Report",
        "docx" => "Word Document",
        "xlsx" => "Excel Spreadsheet", 
        "apk" => "Android Package",
        _ => "ZIP Archive",
    };
    
    fields.push(MetadataField {
        key: "Format".to_string(),
        value: format_name.to_string(),
        category: "Format".to_string(), ..Default::default()
    });
    
    // Version needed at offset 4-6
    if header.len() >= 6 {
        let version = u16::from_le_bytes([header[4], header[5]]);
        
        regions.push(HeaderRegion {
            start: 4,
            end: 6,
            name: "Version Needed".to_string(),
            color_class: "region-version".to_string(),
            description: "Minimum ZIP version needed to extract".to_string(),
        });
        
        fields.push(MetadataField {
            key: "ZIP Version".to_string(),
            value: format!("{}.{}", version / 10, version % 10),
            category: "Format".to_string(), ..Default::default()
        });
    }
    
    // General purpose flag at offset 6-8
    if header.len() >= 8 {
        let flags = u16::from_le_bytes([header[6], header[7]]);
        
        regions.push(HeaderRegion {
            start: 6,
            end: 8,
            name: "Flags".to_string(),
            color_class: "region-flags".to_string(),
            description: "General purpose bit flags".to_string(),
        });
        
        let encrypted = (flags & 0x01) != 0;
        fields.push(MetadataField {
            key: "Encrypted".to_string(),
            value: if encrypted { "Yes" } else { "No" }.to_string(),
            category: "Security".to_string(), ..Default::default()
        });
    }
    
    // Compression method at offset 8-10
    if header.len() >= 10 {
        let method = u16::from_le_bytes([header[8], header[9]]);
        
        regions.push(HeaderRegion {
            start: 8,
            end: 10,
            name: "Compression".to_string(),
            color_class: "region-compression".to_string(),
            description: "Compression method".to_string(),
        });
        
        let method_name = match method {
            0 => "None (Stored)",
            8 => "Deflate",
            12 => "BZIP2",
            14 => "LZMA",
            _ => "Unknown",
        };
        
        fields.push(MetadataField {
            key: "Compression".to_string(),
            value: method_name.to_string(),
            category: "Format".to_string(),
            ..Default::default()
        });
    }
    
    // Filename length at offset 26-28
    if header.len() >= 30 {
        let filename_len = u16::from_le_bytes([header[26], header[27]]) as usize;
        
        regions.push(HeaderRegion {
            start: 26,
            end: 30,
            name: "Length Fields".to_string(),
            color_class: "region-length".to_string(),
            description: "Filename and extra field lengths".to_string(),
        });
        
        // Extract filename if present
        if header.len() >= 30 + filename_len {
            let filename = String::from_utf8_lossy(&header[30..30 + filename_len]);
            
            regions.push(HeaderRegion {
                start: 30,
                end: (30 + filename_len) as u64,
                name: "First Filename".to_string(),
                color_class: "region-data".to_string(),
                description: "Name of first file in archive".to_string(),
            });
            
            fields.push(MetadataField {
                key: "First Entry".to_string(),
                value: filename.to_string(),
                category: "Contents".to_string(),
                ..Default::default()
            });
        }
    }
    
    fields.push(MetadataField {
        key: "File Size".to_string(),
        value: format_size(file_size),
        category: "General".to_string(),
        ..Default::default()
    });
    
    Ok(ParsedMetadata {
        format: format_name.to_string(),
        version: Some("ZIP".to_string()),
        fields,
        regions,
    })
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if bytes >= GB {
        format!("{:.2} GB ({} bytes)", bytes as f64 / GB as f64, bytes)
    } else if bytes >= MB {
        format!("{:.2} MB ({} bytes)", bytes as f64 / MB as f64, bytes)
    } else if bytes >= KB {
        format!("{:.2} KB ({} bytes)", bytes as f64 / KB as f64, bytes)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Read file as text (for text viewer)
pub fn read_file_text(path: &str, offset: u64, max_chars: usize) -> Result<String, String> {
    let chunk = read_file_chunk(path, offset, Some(max_chars * 4))?; // UTF-8 can be up to 4 bytes per char
    
    // Try to decode as UTF-8, falling back to lossy conversion
    let text = String::from_utf8_lossy(&chunk.bytes);
    
    // Truncate to max chars if needed
    if text.chars().count() > max_chars {
        Ok(text.chars().take(max_chars).collect())
    } else {
        Ok(text.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 bytes");
        assert_eq!(format_size(1024), "1.00 KB (1024 bytes)");
        assert_eq!(format_size(1048576), "1.00 MB (1048576 bytes)");
    }
    
    #[test]
    fn test_is_likely_text() {
        assert!(is_likely_text(b"Hello World!"));
        assert!(is_likely_text(b"Line 1\nLine 2\r\n"));
        assert!(!is_likely_text(&[0x00, 0x01, 0x02, 0x03]));
    }
}
