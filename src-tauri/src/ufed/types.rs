//! UFED types and data structures
//!
//! Types for Universal Forensic Extraction Data (UFED) container formats
//! commonly used in mobile device forensics.

use serde::Serialize;

/// UFED file extensions for detection
pub const UFED_EXTENSIONS: &[&str] = &[".ufdr", ".ufdx", ".ufd"];

/// UFED container format type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum UfedFormat {
    /// UFD - Universal Forensic Device extraction metadata (INI format)
    Ufd,
    /// UFDR - UFED Reader format (standalone extraction file)
    Ufdr,
    /// UFDX - Extraction index/metadata file (XML format)
    Ufdx,
    /// ZIP - UFED extraction archive with sibling UFD metadata
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
    /// Whether this appears to be part of a complete UFED extraction set
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

/// Stored hash value from [SHA256], [SHA1], [MD5] sections
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
