//! UFED collection and extraction set handling
//!
//! Functions for finding associated files, collection metadata,
//! and managing complete extraction sets.

use std::path::Path;

use super::detection::is_ufed;
use super::parsing::parse_ufdx_file;
use super::types::{AssociatedFile, CollectionInfo, StoredHash, UfedFormat};

/// Find and parse EvidenceCollection.ufdx in parent directories
/// 
/// Walks up the directory tree (up to 3 levels) looking for the collection file.
pub fn find_collection_ufdx(path: &Path) -> Option<CollectionInfo> {
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

/// Find associated files in the same directory and parent
/// 
/// Lists ALL files for complete visibility of the extraction set,
/// including stored hash lookups from the UFD file.
pub fn find_associated_files(path: &Path, stored_hashes: Option<&Vec<StoredHash>>) -> Vec<AssociatedFile> {
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
                    let file_type = "UFDX".to_string();
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
    } else if filename_lower.ends_with(".xlsx") {
        "XLSX".to_string()
    } else {
        "Other".to_string()
    }
}

/// Check if the associated files form a complete extraction set
/// 
/// A complete set typically has:
/// - A ZIP file (compressed extraction)
/// - A UFD or UFDX file (metadata)
/// - Optionally a PDF/XLSX report
pub fn check_extraction_set(associated: &[AssociatedFile], format: UfedFormat) -> bool {
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
/// 
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
