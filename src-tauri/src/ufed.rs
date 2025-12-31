//! Cellebrite UFED container support (UFD, UFDR, UFDX)
//!
//! This module provides detection and metadata extraction for Cellebrite UFED
//! forensic extraction containers commonly used in mobile device forensics.
//!
//! ## Supported Formats
//! - **UFD**: Cellebrite Universal Forensic Device extraction (folder-based)
//! - **UFDR**: Cellebrite UFED Reader format (single file, often large)
//! - **UFDX**: Cellebrite extraction index/metadata file
//!
//! ## Typical Structure
//! ```text
//! 02606-0900_1E_BTPLJM/                     # Evidence number folder
//! └── UFED Apple iPhone SE (A2275) 2024_08_26 (001)/
//!     └── AdvancedLogical File System 01/
//!         ├── Apple_iPhone SE (A2275)/      # Extracted file system
//!         ├── Apple_iPhone SE (A2275).ufd   # UFD metadata (INI format)
//!         ├── Apple_iPhone SE (A2275).zip   # Compressed extraction
//!         └── SummaryReport.pdf             # Report
//! ```
//!
//! ## UFD File Format
//! UFD files are INI-style configuration files containing:
//! - `[Crime Case]`: Case identifier, examiner, evidence number
//! - `[DeviceInfo]`: IMEI, model, OS version, vendor
//! - `[General]`: Acquisition tool, extraction type, timestamps
//! - `[SHA256]`: Hash values for extraction files
//! - `[Hash]`: HMAC verification

use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::io::{BufRead, BufReader};
use std::fs::File;
use tracing::debug;

/// Cellebrite file extensions to detect
pub const CELLEBRITE_EXTENSIONS: &[&str] = &[".ufdr", ".ufdx", ".ufd"];

/// UFED container format type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum UfedFormat {
    /// UFD - Universal Forensic Device extraction metadata
    Ufd,
    /// UFDR - UFED Reader format (standalone extraction file)
    Ufdr,
    /// UFDX - Extraction index/metadata file
    Ufdx,
    /// ZIP - UFED extraction archive (evidence container with sibling UFD metadata)
    UfedZip,
}

impl std::fmt::Display for UfedFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UfedFormat::Ufd => write!(f, "UFD"),
            UfedFormat::Ufdr => write!(f, "UFDR"),
            UfedFormat::Ufdx => write!(f, "UFDX"),
            UfedFormat::UfedZip => write!(f, "ZIP"),
        }
    }
}

/// UFED container information
#[derive(Debug, Clone, Serialize)]
pub struct UfedInfo {
    /// Format type (UFD, UFDR, UFDX)
    pub format: String,
    /// File size in bytes
    pub size: u64,
    /// Parent directory name (often contains device info)
    pub parent_folder: Option<String>,
    /// Associated files found in the same directory
    pub associated_files: Vec<AssociatedFile>,
    /// Whether this appears to be part of a Cellebrite extraction set
    pub is_extraction_set: bool,
    /// Device info extracted from path/filename if available
    pub device_hint: Option<String>,
    /// Case/Crime information from UFD file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_info: Option<CaseInfo>,
    /// Device details from UFD file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_info: Option<DeviceInfo>,
    /// Extraction/acquisition details from UFD file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extraction_info: Option<ExtractionInfo>,
    /// SHA256 hashes from UFD file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_hashes: Option<Vec<StoredHash>>,
    /// Evidence number derived from folder structure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_number: Option<String>,
    /// Collection-level info from EvidenceCollection.ufdx
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_info: Option<CollectionInfo>,
}

/// Collection-level information from EvidenceCollection.ufdx
#[derive(Debug, Clone, Serialize)]
pub struct CollectionInfo {
    /// Evidence ID (GUID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    /// Device vendor from UFDX
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Device model from UFDX
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Device GUID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_guid: Option<String>,
    /// List of extraction paths in this collection
    pub extractions: Vec<String>,
    /// UFDX file path
    pub ufdx_path: String,
}

/// Case/Crime information from [Crime Case] section
#[derive(Debug, Clone, Serialize)]
pub struct CaseInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub examiner_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// Device information from [DeviceInfo] section
#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imei2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iccid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
}

/// Extraction/acquisition information from [General] section
#[derive(Debug, Clone, Serialize)]
pub struct ExtractionInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acquisition_tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extraction_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_name: Option<String>,
}

/// Stored hash value from [SHA256] section
#[derive(Debug, Clone, Serialize)]
pub struct StoredHash {
    pub filename: String,
    pub algorithm: String,
    pub hash: String,
}

/// Associated file in a UFED extraction
#[derive(Debug, Clone, Serialize)]
pub struct AssociatedFile {
    pub filename: String,
    pub file_type: String,
    pub size: u64,
    /// SHA256 hash if available from UFD file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_hash: Option<String>,
}

/// Check if a file is a Cellebrite UFED format
/// This includes:
/// - .ufd, .ufdr, .ufdx by extension
/// - .zip files that have a sibling .ufd file with the same basename
pub fn is_ufed(path: &str) -> bool {
    let lower = path.to_lowercase();
    
    // Check standard UFED extensions
    if CELLEBRITE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
        return true;
    }
    
    // Check if it's a ZIP file with a sibling UFD file
    if lower.ends_with(".zip") {
        if let Some(ufd_path) = find_sibling_ufd(path) {
            return ufd_path.exists();
        }
    }
    
    false
}

/// Find the sibling UFD file for a given path (if basename matches)
fn find_sibling_ufd(path: &str) -> Option<std::path::PathBuf> {
    let path_obj = Path::new(path);
    let stem = path_obj.file_stem()?.to_string_lossy();
    let parent = path_obj.parent()?;
    let ufd_path = parent.join(format!("{}.ufd", stem));
    Some(ufd_path)
}

/// Check if a filename is a Cellebrite file
pub fn is_cellebrite_file(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    CELLEBRITE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Detect UFED format from file extension and context
pub fn detect_ufed_format(path: &str) -> Option<UfedFormat> {
    let lower = path.to_lowercase();
    
    if lower.ends_with(".ufdr") {
        Some(UfedFormat::Ufdr)
    } else if lower.ends_with(".ufdx") {
        Some(UfedFormat::Ufdx)
    } else if lower.ends_with(".ufd") {
        Some(UfedFormat::Ufd)
    } else if lower.ends_with(".zip") {
        // Check if it has a sibling UFD file
        if let Some(ufd_path) = find_sibling_ufd(path) {
            if ufd_path.exists() {
                return Some(UfedFormat::UfedZip);
            }
        }
        None
    } else {
        None
    }
}

/// Get UFED container information
pub fn info(path: &str) -> Result<UfedInfo, String> {
    debug!(path = %path, "Getting UFED info");
    
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("UFED file not found: {path}"));
    }
    
    let format = detect_ufed_format(path)
        .ok_or_else(|| format!("Not a recognized UFED format: {path}"))?;
    
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("Failed to read file metadata: {e}"))?;
    
    let size = metadata.len();
    
    // Get parent folder name (often contains device info)
    let parent_folder = path_obj
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());
    
    // Try to extract device hint from filename or path
    let device_hint = extract_device_hint(path);
    
    // Extract evidence number from folder structure
    let evidence_number = extract_evidence_number(path_obj);
    
    // Parse UFD file contents:
    // - If it's a .ufd file, parse it directly
    // - If it's a UFED ZIP, find and parse the sibling .ufd file
    let (case_info, device_info, extraction_info, stored_hashes) = match format {
        UfedFormat::Ufd => parse_ufd_file(path)?,
        UfedFormat::UfedZip => {
            // Find sibling UFD and parse it
            if let Some(ufd_path) = find_sibling_ufd(path) {
                if ufd_path.exists() {
                    if let Some(ufd_str) = ufd_path.to_str() {
                        parse_ufd_file(ufd_str).unwrap_or((None, None, None, None))
                    } else {
                        (None, None, None, None)
                    }
                } else {
                    (None, None, None, None)
                }
            } else {
                (None, None, None, None)
            }
        }
        _ => (None, None, None, None),
    };
    
    // Find associated files in the same directory (with hash info)
    let associated_files = find_associated_files(path_obj, stored_hashes.as_ref());
    
    // Find and parse EvidenceCollection.ufdx in parent directories
    let collection_info = find_collection_ufdx(path_obj);
    
    // Check if this is part of a complete extraction set
    let is_extraction_set = check_extraction_set(&associated_files, format);
    
    debug!(
        path = %path,
        format = %format,
        size = size,
        associated_files = associated_files.len(),
        is_extraction_set = is_extraction_set,
        has_case_info = case_info.is_some(),
        has_device_info = device_info.is_some(),
        has_collection_info = collection_info.is_some(),
        "UFED info loaded"
    );
    
    Ok(UfedInfo {
        format: format.to_string(),
        size,
        parent_folder,
        associated_files,
        is_extraction_set,
        device_hint,
        case_info,
        device_info,
        extraction_info,
        stored_hashes,
        evidence_number,
        collection_info,
    })
}

/// Parse UFD file (INI-style format) and extract metadata
fn parse_ufd_file(path: &str) -> Result<(Option<CaseInfo>, Option<DeviceInfo>, Option<ExtractionInfo>, Option<Vec<StoredHash>>), String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open UFD file: {e}"))?;
    
    let reader = BufReader::new(file);
    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current_section = String::new();
    
    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read UFD file: {e}"))?;
        let line = line.trim();
        
        // Skip empty lines
        if line.is_empty() {
            continue;
        }
        
        // Check for section header [SectionName]
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len()-1].to_string();
            sections.entry(current_section.clone()).or_default();
            continue;
        }
        
        // Parse key=value pairs
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let value = line[eq_pos+1..].trim().to_string();
            
            if !current_section.is_empty() {
                sections.get_mut(&current_section)
                    .map(|s| s.insert(key, value));
            }
        }
    }
    
    // Extract Case Info from [Crime Case] section
    let case_info = sections.get("Crime Case").map(|s| CaseInfo {
        case_identifier: s.get("Case Identifier").cloned().filter(|v| !v.is_empty()),
        crime_type: s.get("Crime Type").cloned().filter(|v| !v.is_empty()),
        department: s.get("Department").cloned().filter(|v| !v.is_empty()),
        device_name: s.get("Device Name / Evidence Number").cloned().filter(|v| !v.is_empty()),
        examiner_name: s.get("Examiner Name").cloned().filter(|v| !v.is_empty()),
        location: s.get("Location").cloned().filter(|v| !v.is_empty()),
    });
    
    // Extract Device Info from [DeviceInfo] and [General] sections
    let device_section = sections.get("DeviceInfo");
    let general_section = sections.get("General");
    
    let device_info = if device_section.is_some() || general_section.is_some() {
        Some(DeviceInfo {
            vendor: general_section.and_then(|s| s.get("Vendor").cloned())
                .or_else(|| device_section.and_then(|s| s.get("Vendor").cloned()))
                .filter(|v| !v.is_empty()),
            model: device_section.and_then(|s| s.get("Model").cloned())
                .filter(|v| !v.is_empty()),
            full_name: general_section.and_then(|s| s.get("FullName").cloned())
                .or_else(|| general_section.and_then(|s| s.get("Model").cloned()))
                .filter(|v| !v.is_empty()),
            imei: device_section.and_then(|s| s.get("IMEI1").cloned())
                .or_else(|| device_section.and_then(|s| s.get("IMEI").cloned()))
                .filter(|v| !v.is_empty()),
            imei2: device_section.and_then(|s| s.get("IMEI2").cloned())
                .filter(|v| !v.is_empty()),
            iccid: device_section.and_then(|s| s.get("ICCID").cloned())
                .filter(|v| !v.is_empty()),
            os_version: device_section.and_then(|s| s.get("OS").cloned())
                .filter(|v| !v.is_empty()),
            serial_number: device_section.and_then(|s| s.get("SerialNumber").cloned())
                .filter(|v| !v.is_empty()),
        })
    } else {
        None
    };
    
    // Extract Extraction Info from [General] section
    let extraction_info = general_section.map(|s| ExtractionInfo {
        acquisition_tool: s.get("AcquisitionTool").cloned().filter(|v| !v.is_empty()),
        tool_version: s.get("Version").cloned().filter(|v| !v.is_empty()),
        unit_id: s.get("UnitId").cloned().filter(|v| !v.is_empty()),
        extraction_type: s.get("ExtractionType").cloned().filter(|v| !v.is_empty()),
        connection_type: s.get("ConnectionType").cloned().filter(|v| !v.is_empty()),
        start_time: s.get("Date").cloned().filter(|v| !v.is_empty()),
        end_time: s.get("EndTime").cloned().filter(|v| !v.is_empty()),
        guid: s.get("GUID").cloned().filter(|v| !v.is_empty()),
        machine_name: s.get("MachineName").cloned().filter(|v| !v.is_empty()),
    });
    
    // Extract stored hashes from [SHA256], [SHA1], [MD5] sections
    let mut stored_hashes = Vec::new();
    
    for (algo, section_name) in [("SHA256", "SHA256"), ("SHA1", "SHA1"), ("MD5", "MD5")] {
        if let Some(section) = sections.get(section_name) {
            for (filename, hash) in section.iter() {
                stored_hashes.push(StoredHash {
                    filename: filename.clone(),
                    algorithm: algo.to_string(),
                    hash: hash.clone(),
                });
            }
        }
    }
    
    let stored_hashes = if stored_hashes.is_empty() { None } else { Some(stored_hashes) };
    
    Ok((case_info, device_info, extraction_info, stored_hashes))
}

/// Find and parse EvidenceCollection.ufdx in parent directories
/// Walks up the directory tree looking for the collection file
fn find_collection_ufdx(path: &Path) -> Option<CollectionInfo> {
    let mut current = path.parent();
    
    // Walk up to 3 levels looking for EvidenceCollection.ufdx
    for _ in 0..3 {
        let Some(dir) = current else { break };
        
        // Look for EvidenceCollection.ufdx in this directory
        let ufdx_path = dir.join("EvidenceCollection.ufdx");
        if ufdx_path.exists() {
            if let Some(info) = parse_ufdx_file(&ufdx_path) {
                return Some(info);
            }
        }
        
        current = dir.parent();
    }
    
    None
}

/// Parse EvidenceCollection.ufdx (XML format)
fn parse_ufdx_file(path: &Path) -> Option<CollectionInfo> {
    let content = std::fs::read_to_string(path).ok()?;
    
    // Simple XML parsing - extract key attributes
    let evidence_id = extract_xml_attr(&content, "EvidenceID");
    let vendor = extract_xml_attr(&content, "Vendor");
    let model = extract_xml_attr(&content, "Model");
    let device_guid = extract_xml_attr(&content, "Guid");
    
    // Extract extraction paths
    let mut extractions = Vec::new();
    for line in content.lines() {
        if line.contains("<Extraction") && line.contains("Path=") {
            if let Some(path_val) = extract_xml_attr(line, "Path") {
                extractions.push(path_val);
            }
        }
    }
    
    Some(CollectionInfo {
        evidence_id,
        vendor,
        model,
        device_guid,
        extractions,
        ufdx_path: path.to_string_lossy().to_string(),
    })
}

/// Extract an XML attribute value from a string
fn extract_xml_attr(content: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr_name);
    let start = content.find(&pattern)?;
    let value_start = start + pattern.len();
    let value_end = content[value_start..].find('"')? + value_start;
    Some(content[value_start..value_end].to_string())
}

/// Extract evidence number from folder structure
/// Looks for patterns like "02606-0900_1E_BTPLJM" in parent folders
fn extract_evidence_number(path: &Path) -> Option<String> {
    let mut current = path.parent();
    
    // Walk up the directory tree looking for evidence number patterns
    while let Some(dir) = current {
        if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
            // Skip extraction-related folder names
            let lower = name.to_lowercase();
            if lower.contains("ufed") || lower.contains("file system") || lower.contains("advancedlogical") {
                current = dir.parent();
                continue;
            }
            
            // Evidence number patterns: contain underscores, dashes, alphanumeric
            // e.g., "02606-0900_1E_BTPLJM", "12345-0001_A_XYZ123"
            if name.contains('_') && name.contains('-') && name.len() >= 10 {
                return Some(name.to_string());
            }
            
            // Also check for simpler patterns like case numbers
            if name.chars().filter(|c| c.is_ascii_digit()).count() >= 4 {
                // Has at least 4 digits, might be a case/evidence number
                if name.contains('-') || name.contains('_') {
                    return Some(name.to_string());
                }
            }
        }
        current = dir.parent();
    }
    
    None
}

/// Extract device hint from filename or path
fn extract_device_hint(path: &str) -> Option<String> {
    let path_obj = Path::new(path);
    let filename = path_obj.file_stem()?.to_str()?;
    
    // Common patterns in Cellebrite filenames:
    // - "Apple_iPhone SE (A2275)"
    // - "Samsung GSM_SM-S918U Galaxy S23 Ultra"
    // - Device model numbers
    
    // Check if filename contains device-like patterns
    let lower = filename.to_lowercase();
    if lower.contains("iphone") || lower.contains("ipad") || lower.contains("samsung") 
        || lower.contains("galaxy") || lower.contains("pixel") || lower.contains("android")
        || lower.contains("apple") || lower.contains("huawei") || lower.contains("oneplus")
    {
        return Some(filename.to_string());
    }
    
    // Check parent folder for UFED extraction pattern
    if let Some(parent) = path_obj.parent() {
        if let Some(parent_name) = parent.file_name().and_then(|n| n.to_str()) {
            let parent_lower = parent_name.to_lowercase();
            if parent_lower.contains("ufed") || parent_lower.contains("advancedlogical") 
                || parent_lower.contains("file system")
            {
                // Go up one more level to find device info
                if let Some(grandparent) = parent.parent() {
                    if let Some(gp_name) = grandparent.file_name().and_then(|n| n.to_str()) {
                        if gp_name.to_lowercase().contains("ufed") {
                            // Extract device name from "UFED Apple iPhone SE (A2275) 2024_08_26 (001)"
                            return extract_device_from_ufed_folder(gp_name);
                        }
                    }
                }
            }
        }
    }
    
    None
}

/// Extract device name from UFED folder naming convention
fn extract_device_from_ufed_folder(folder_name: &str) -> Option<String> {
    // Pattern: "UFED <Device Name> <Date> (<Number>)"
    // Example: "UFED Apple iPhone SE (A2275) 2024_08_26 (001)"
    
    let name = folder_name.trim();
    
    // Remove "UFED " prefix
    let without_prefix = if name.to_lowercase().starts_with("ufed ") {
        &name[5..]
    } else {
        name
    };
    
    // Try to find the date pattern (YYYY_MM_DD or similar) and extract what's before it
    if let Some(date_pos) = find_date_pattern(without_prefix) {
        let device = without_prefix[..date_pos].trim();
        if !device.is_empty() {
            return Some(device.to_string());
        }
    }
    
    // Fallback: return the whole thing without UFED prefix
    if !without_prefix.is_empty() {
        return Some(without_prefix.to_string());
    }
    
    None
}

/// Find position of date pattern in string
fn find_date_pattern(s: &str) -> Option<usize> {
    // Look for patterns like "2024_08_26" or "2024-08-26"
    let chars: Vec<char> = s.chars().collect();
    
    for i in 0..chars.len().saturating_sub(9) {
        // Check for YYYY_MM_DD or YYYY-MM-DD
        if chars[i].is_ascii_digit() 
            && chars.get(i + 4).map(|&c| c == '_' || c == '-').unwrap_or(false)
            && chars.get(i + 7).map(|&c| c == '_' || c == '-').unwrap_or(false)
        {
            // Verify it's a valid date-like pattern
            let is_year = (i..i+4).all(|j| chars.get(j).map(|c| c.is_ascii_digit()).unwrap_or(false));
            let is_month = (i+5..i+7).all(|j| chars.get(j).map(|c| c.is_ascii_digit()).unwrap_or(false));
            let is_day = (i+8..i+10).all(|j| chars.get(j).map(|c| c.is_ascii_digit()).unwrap_or(false));
            
            if is_year && is_month && is_day {
                return Some(i);
            }
        }
    }
    
    None
}

/// Find associated files in the same directory and parent
/// Lists ALL files for complete visibility of the extraction set
fn find_associated_files(path: &Path, stored_hashes: Option<&Vec<StoredHash>>) -> Vec<AssociatedFile> {
    let mut associated = Vec::new();
    
    let Some(parent) = path.parent() else {
        return associated;
    };
    
    // First, scan the same directory (sibling files)
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            
            // Skip the file itself
            if entry_path == path {
                continue;
            }
            
            // Skip directories
            if entry_path.is_dir() {
                continue;
            }
            
            let Some(entry_name) = entry_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            
            // Skip macOS resource fork files and .DS_Store
            if entry_name.starts_with("._") || entry_name == ".DS_Store" {
                continue;
            }
            
            let entry_lower = entry_name.to_lowercase();
            let file_type = determine_file_type(&entry_lower);
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            
            // Look up stored hash for this file if available
            let stored_hash = stored_hashes.and_then(|hashes| {
                hashes.iter()
                    .find(|h| h.filename.to_lowercase() == entry_lower 
                        || entry_lower.contains(&h.filename.to_lowercase()))
                    .map(|h| h.hash.clone())
            });
            
            associated.push(AssociatedFile {
                filename: entry_name.to_string(),
                file_type,
                size,
                stored_hash,
            });
        }
    }
    
    // Also check parent folder for UFDX collection files
    if let Some(grandparent) = parent.parent() {
        if let Ok(entries) = std::fs::read_dir(grandparent) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                
                // Only look at files, not directories
                if entry_path.is_dir() {
                    continue;
                }
                
                let Some(entry_name) = entry_path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                
                let entry_lower = entry_name.to_lowercase();
                
                // Only include UFDX files from parent (collection-level metadata)
                if entry_lower.ends_with(".ufdx") {
                    let file_type = "UFDX".to_string(); // Keep simple for CSS class
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    
                    associated.push(AssociatedFile {
                        filename: format!("../{}", entry_name), // Indicate it's from parent folder
                        file_type,
                        size,
                        stored_hash: None,
                    });
                }
            }
        }
    }
    
    // Sort by file type then name for consistent display
    associated.sort_by(|a, b| {
        a.file_type.cmp(&b.file_type).then_with(|| a.filename.cmp(&b.filename))
    });
    
    associated
}

/// Determine file type from extension
fn determine_file_type(filename_lower: &str) -> String {
    if filename_lower.ends_with(".ufdr") {
        "UFDR".to_string()
    } else if filename_lower.ends_with(".ufdx") {
        "UFDX".to_string()
    } else if filename_lower.ends_with(".ufd") {
        "UFD".to_string()
    } else if filename_lower.ends_with(".zip") {
        "ZIP".to_string()
    } else if filename_lower.ends_with(".pdf") {
        "PDF".to_string()
    } else if filename_lower.ends_with(".xml") {
        "XML".to_string()
    } else {
        "Other".to_string()
    }
}

/// Check if the associated files form a complete extraction set
fn check_extraction_set(associated: &[AssociatedFile], format: UfedFormat) -> bool {
    // A complete set typically has:
    // - A ZIP file (compressed extraction)
    // - A UFD or UFDX file (metadata)
    // - Optionally a PDF report
    
    let has_zip = associated.iter().any(|f| f.file_type == "ZIP");
    let _has_ufd = associated.iter().any(|f| f.file_type == "UFD" || f.file_type == "UFDX");
    let has_pdf = associated.iter().any(|f| f.file_type == "PDF");
    
    match format {
        UfedFormat::Ufd | UfedFormat::Ufdx => has_zip || has_pdf,
        UfedFormat::Ufdr => true, // UFDR is self-contained
        UfedFormat::UfedZip => true, // UfedZip is the main evidence with sibling UFD
    }
}

/// Scan a directory for UFED extractions
/// Returns list of UFED file paths found
pub fn scan_for_ufed_files(dir: &Path, recursive: bool) -> Vec<String> {
    let mut ufed_files = Vec::new();
    scan_directory_for_ufed(dir, recursive, &mut ufed_files);
    ufed_files
}

fn scan_directory_for_ufed(dir: &Path, recursive: bool, results: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    
    for entry in entries.flatten() {
        let path = entry.path();
        
        if path.is_file() {
            if let Some(path_str) = path.to_str() {
                if is_ufed(path_str) {
                    results.push(path_str.to_string());
                }
            }
        } else if recursive && path.is_dir() {
            scan_directory_for_ufed(&path, recursive, results);
        }
    }
}
