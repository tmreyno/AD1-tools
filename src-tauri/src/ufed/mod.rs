//! UFED container support (UFD, UFDR, UFDX)
//!
//! This module provides detection and metadata extraction for UFED
//! (Universal Forensic Extraction Data) containers commonly used in 
//! mobile device forensics.
//!
//! ## Supported Formats
//! - **UFD**: Metadata file (INI format with case/device/hash info)
//! - **UFDR**: Standalone extraction file (often large)
//! - **UFDX**: Collection index/metadata file (XML format)
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
//!
//! ## Module Structure
//! ```text
//! ufed/
//! ├── mod.rs         - Main entry point, info() function
//! ├── types.rs       - UfedFormat, UfedInfo, CaseInfo, DeviceInfo, etc.
//! ├── detection.rs   - Format detection, is_ufed(), device hints
//! ├── parsing.rs     - UFD (INI) and UFDX (XML) parsers
//! ├── collection.rs  - Extraction sets, associated files
//! └── archive_scan.rs - UFED detection inside ZIP archives
//! ```

pub mod types;
pub mod detection;
pub mod parsing;
pub mod collection;
pub mod archive_scan;

// Re-exports for convenience
pub use types::{
    UfedFormat, UfedInfo, CaseInfo, DeviceInfo, ExtractionInfo,
    StoredHash, AssociatedFile, CollectionInfo, UFED_EXTENSIONS,
};
pub use detection::{is_ufed, detect_format, is_ufed_file, find_sibling_ufd};
pub use archive_scan::detect_in_zip;

use std::path::Path;
use tracing::{debug, instrument};

/// Get UFED container information
#[instrument]
pub fn info(path: &str) -> Result<UfedInfo, String> {
    debug!(path = %path, "Getting UFED info");
    
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("UFED file not found: {path}"));
    }
    
    let format = detection::detect_format(path)
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
    let device_hint = detection::extract_device_hint(path);
    
    // Extract evidence number from folder structure
    let evidence_number = detection::extract_evidence_number(path_obj);
    
    // Parse UFD file contents:
    // - If it's a .ufd file, parse it directly
    // - If it's a UFED ZIP, find and parse the sibling .ufd file
    let (case_info, device_info, extraction_info, stored_hashes) = match format {
        UfedFormat::Ufd => parsing::parse_ufd_file(path)?,
        UfedFormat::UfedZip => {
            // Find sibling UFD and parse it
            if let Some(ufd_path) = detection::find_sibling_ufd(path) {
                if ufd_path.exists() {
                    if let Some(ufd_str) = ufd_path.to_str() {
                        parsing::parse_ufd_file(ufd_str).unwrap_or((None, None, None, None))
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
    let associated_files = collection::find_associated_files(path_obj, stored_hashes.as_ref());
    
    // Find and parse EvidenceCollection.ufdx in parent directories
    let collection_info = collection::find_collection_ufdx(path_obj);
    
    // Check if this is part of a complete extraction set
    let is_extraction_set = collection::check_extraction_set(&associated_files, format);
    
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
