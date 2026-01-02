//! UFED format detection
//!
//! Detection functions for UFED container formats based on
//! file extensions and sibling file patterns.

use std::path::Path;
use tracing::{trace, instrument};

use super::types::{UfedFormat, UFED_EXTENSIONS};

/// Check if a file is a UFED format
/// 
/// This includes:
/// - .ufd, .ufdr, .ufdx by extension
/// - .zip files that have a sibling .ufd file with the same basename
#[instrument]
pub fn is_ufed(path: &str) -> bool {
    let lower = path.to_lowercase();
    
    // Check standard UFED extensions
    if UFED_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
        trace!("Matched UFED by extension");
        return true;
    }
    
    // Check if it's a ZIP file with a sibling UFD file
    if lower.ends_with(".zip") {
        if let Some(ufd_path) = find_sibling_ufd(path) {
            let exists = ufd_path.exists();
            trace!(?ufd_path, exists, "Checking for sibling UFD");
            return exists;
        }
    }
    
    false
}

/// Check if a filename has a UFED extension
pub fn is_ufed_file(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    UFED_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Detect UFED format from file extension and context
#[instrument]
pub fn detect_format(path: &str) -> Option<UfedFormat> {
    let lower = path.to_lowercase();
    
    let format = if lower.ends_with(".ufdr") {
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
    };
    
    trace!(?format, "Detected UFED format");
    format
}

/// Find the sibling UFD file for a given path (if basename matches)
pub fn find_sibling_ufd(path: &str) -> Option<std::path::PathBuf> {
    let path_obj = Path::new(path);
    let stem = path_obj.file_stem()?.to_string_lossy();
    let parent = path_obj.parent()?;
    let ufd_path = parent.join(format!("{}.ufd", stem));
    Some(ufd_path)
}

/// Extract device hint from filename or path
/// 
/// Looks for device-like patterns in UFED folder names such as:
/// - "Apple_iPhone SE (A2275)"
/// - "Samsung GSM_SM-S918U Galaxy S23 Ultra"
pub fn extract_device_hint(path: &str) -> Option<String> {
    let path_obj = Path::new(path);
    let filename = path_obj.file_stem()?.to_str()?;
    
    // Common patterns in UFED filenames
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
/// 
/// Pattern: "UFED <Device Name> <Date> (<Number>)"
/// Example: "UFED Apple iPhone SE (A2275) 2024_08_26 (001)"
fn extract_device_from_ufed_folder(folder_name: &str) -> Option<String> {
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

/// Find position of date pattern in string (YYYY_MM_DD or YYYY-MM-DD)
fn find_date_pattern(s: &str) -> Option<usize> {
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

/// Extract evidence number from folder structure
/// 
/// Looks for patterns like "02606-0900_1E_BTPLJM" in parent folders
pub fn extract_evidence_number(path: &Path) -> Option<String> {
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
