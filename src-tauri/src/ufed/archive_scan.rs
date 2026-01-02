//! UFED detection in archive files
//!
//! Scans ZIP archives for embedded UFED files (UFDR/UFDX/UFD),
//! including nested ZIP files.

use std::fs::File;
use std::io::Read;
use tracing::debug;

use super::types::UFED_EXTENSIONS;

/// Check if a filename has a UFED extension
pub fn is_ufed_file(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    UFED_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Detect UFED files (UFDR/UFDX/UFD) inside a ZIP archive
/// 
/// Also checks nested ZIPs (one level deep) that might contain UFED files.
/// 
/// Returns: (detected, list of UFED file paths found)
pub fn detect_in_zip(path: &str) -> Result<(bool, Vec<String>), String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open ZIP: {e}"))?;
    
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| format!("Failed to read ZIP archive: {e}"))?;
    
    let mut ufed_files: Vec<String> = Vec::new();
    let mut nested_zips: Vec<String> = Vec::new();
    
    // First pass: scan all entries in the archive
    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            let name = entry.name().to_string();
            let lower_name = name.to_lowercase();
            
            // Check for UFED files
            if is_ufed_file(&lower_name) {
                debug!(path = %path, entry = %name, "Found UFED file in ZIP");
                ufed_files.push(name.clone());
            }
            
            // Track nested ZIP files for deeper inspection
            if lower_name.ends_with(".zip") {
                nested_zips.push(name);
            }
        }
    }
    
    // Second pass: check inside nested ZIPs (one level deep)
    for nested_zip_name in &nested_zips {
        if let Ok(nested_files) = scan_nested_zip(&mut archive, nested_zip_name) {
            for nested_file in nested_files {
                let full_path = format!("{}/{}", nested_zip_name, nested_file);
                debug!(path = %path, entry = %full_path, "Found UFED file in nested ZIP");
                ufed_files.push(full_path);
            }
        }
    }
    
    let detected = !ufed_files.is_empty();
    
    if detected {
        debug!(
            path = %path,
            count = ufed_files.len(),
            files = ?ufed_files,
            "UFED files detected in archive"
        );
    }
    
    Ok((detected, ufed_files))
}

/// Scan a nested ZIP inside the parent archive for UFED files
fn scan_nested_zip(
    parent_archive: &mut zip::ZipArchive<File>,
    nested_zip_name: &str,
) -> Result<Vec<String>, String> {
    use std::io::Cursor;
    
    let mut ufed_files: Vec<String> = Vec::new();
    
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
            if is_ufed_file(&name) {
                ufed_files.push(name);
            }
        }
    }
    
    Ok(ufed_files)
}
