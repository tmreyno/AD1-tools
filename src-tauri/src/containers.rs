use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use regex::Regex;
use tracing::debug;

use crate::ad1;
use crate::archive;  // Archive formats (7z, ZIP, RAR)
use crate::ewf;  // Expert Witness Format (E01/EWF/Ex01)
use crate::l01;
use crate::raw;  // Raw disk images (.dd, .raw, .img, .001)

/// Pre-compiled regex for matching hex hash values (32-128 chars)
/// Compiled once on first use via OnceLock
fn hash_regex() -> &'static Regex {
    static HASH_REGEX: OnceLock<Regex> = OnceLock::new();
    HASH_REGEX.get_or_init(|| {
        Regex::new(r"[a-fA-F0-9]{32,128}").expect("Invalid hash regex")
    })
}

#[derive(Serialize, Clone)]
pub struct StoredHash {
    pub algorithm: String,
    pub hash: String,
    pub verified: Option<bool>,  // None if not verified, Some(true) if verified, Some(false) if mismatch
    pub timestamp: Option<String>,  // When hash was created/verified (ISO 8601 or human-readable)
    pub source: Option<String>,     // Where hash came from: "container", "companion", "computed"
}

/// Per-segment hash information from companion log files
#[derive(Serialize, Deserialize, Clone)]
pub struct SegmentHash {
    pub segment_name: String,       // e.g., "SCHARDT.001"
    pub segment_number: u32,        // e.g., 1
    pub algorithm: String,          // e.g., "MD5"
    pub hash: String,               // The hash value
    pub offset_from: Option<u64>,   // Starting byte/sector offset
    pub offset_to: Option<u64>,     // Ending byte/sector offset
    pub size: Option<u64>,          // Segment size
    pub verified: Option<bool>,     // Verification status
}

#[derive(Serialize, Clone)]
pub struct CompanionLogInfo {
    pub log_path: String,
    pub created_by: Option<String>,
    pub case_number: Option<String>,
    pub evidence_number: Option<String>,
    pub unique_description: Option<String>,
    pub examiner: Option<String>,
    pub notes: Option<String>,
    pub acquisition_started: Option<String>,
    pub acquisition_finished: Option<String>,
    pub verification_started: Option<String>,
    pub verification_finished: Option<String>,
    pub stored_hashes: Vec<StoredHash>,
    pub segment_list: Vec<String>,
    pub segment_hashes: Vec<SegmentHash>,  // Per-segment hashes
}

#[derive(Serialize)]
pub struct ContainerInfo {
    pub container: String,
    pub ad1: Option<ad1::Ad1Info>,
    pub e01: Option<ewf::E01Info>,
    pub l01: Option<l01::L01Info>,
    pub raw: Option<raw::RawInfo>,
    pub archive: Option<archive::ArchiveInfo>,
    pub note: Option<String>,
    pub companion_log: Option<CompanionLogInfo>,
}

#[derive(Clone, Serialize)]
pub struct DiscoveredFile {
    pub path: String,
    pub filename: String,
    pub container_type: String,
    pub size: u64,
    pub segment_count: Option<u32>,
    pub segment_files: Option<Vec<String>>,
    pub segment_sizes: Option<Vec<u64>>,
    pub total_segment_size: Option<u64>,
    pub created: Option<String>,
    pub modified: Option<String>,
}

#[derive(Serialize)]
pub struct VerifyEntry {
    pub path: Option<String>,
    pub chunk_index: Option<usize>,
    pub status: String,
    pub message: Option<String>,
}

enum ContainerKind {
    Ad1,
    E01,
    L01,
    Raw,
    Archive,
}

/// Fast info - only reads headers, doesn't parse full item trees
/// Use this for quick container listing/display
pub fn info_fast(path: &str) -> Result<ContainerInfo, String> {
    debug!("info_fast: loading {}", path);
    let kind = detect_container(path).map_err(|e| {
        debug!("info_fast: detect_container failed for {}: {}", path, e);
        e
    })?;
    let companion_log = find_companion_log(path);
    
    match kind {
        ContainerKind::Ad1 => {
            let info = ad1::info_fast(path)?;
            Ok(ContainerInfo {
                container: "AD1".to_string(),
                ad1: Some(info),
                e01: None,
                l01: None,
                raw: None,
                archive: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::E01 => {
            let info = ewf::info(path)?;
            Ok(ContainerInfo {
                container: "E01".to_string(),
                ad1: None,
                e01: Some(info),
                l01: None,
                raw: None,
                archive: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::L01 => {
            let info = l01::info(path)?;
            Ok(ContainerInfo {
                container: "L01".to_string(),
                ad1: None,
                e01: None,
                l01: Some(info),
                raw: None,
                archive: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::Raw => {
            let info = raw::info(path)?;
            Ok(ContainerInfo {
                container: "RAW".to_string(),
                ad1: None,
                e01: None,
                l01: None,
                raw: Some(info),
                archive: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::Archive => {
            let info = archive::info(path)?;
            Ok(ContainerInfo {
                container: format!("Archive ({})", info.format),
                ad1: None,
                e01: None,
                l01: None,
                raw: None,
                archive: Some(info),
                note: None,
                companion_log,
            })
        }
    }
}

pub fn info(path: &str, include_tree: bool) -> Result<ContainerInfo, String> {
    let kind = detect_container(path)?;
    // Try to find and parse companion log file
    let companion_log = find_companion_log(path);
    
    match kind {
        ContainerKind::Ad1 => {
            let info = ad1::info(path, include_tree)?;
            Ok(ContainerInfo {
                container: "AD1".to_string(),
                ad1: Some(info),
                e01: None,
                l01: None,
                raw: None,
                archive: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::E01 => {
            let info = ewf::info(path)?;
            Ok(ContainerInfo {
                container: "E01".to_string(),
                ad1: None,
                e01: Some(info),
                l01: None,
                raw: None,
                archive: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::L01 => {
            let info = l01::info(path)?;
            Ok(ContainerInfo {
                container: "L01".to_string(),
                ad1: None,
                e01: None,
                l01: Some(info),
                raw: None,
                archive: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::Raw => {
            let info = raw::info(path)?;
            Ok(ContainerInfo {
                container: "RAW".to_string(),
                ad1: None,
                e01: None,
                l01: None,
                raw: Some(info),
                archive: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::Archive => {
            let info = archive::info(path)?;
            Ok(ContainerInfo {
                container: format!("Archive ({})", info.format),
                ad1: None,
                e01: None,
                l01: None,
                raw: None,
                archive: Some(info),
                note: None,
                companion_log,
            })
        }
    }
}

pub fn verify(path: &str, algorithm: &str) -> Result<Vec<VerifyEntry>, String> {
    match detect_container(path)? {
        ContainerKind::Ad1 => {
            let ad1_results = ad1::verify(path, algorithm)?;
            Ok(ad1_results.into_iter().map(|entry| VerifyEntry {
                path: Some(entry.path),
                chunk_index: None,
                status: entry.status,
                message: None,
            }).collect())
        }
        ContainerKind::E01 => {
            let ewf_results = ewf::verify_chunks(path, algorithm)?;
            Ok(ewf_results.into_iter().map(|entry| VerifyEntry {
                path: None,
                chunk_index: Some(entry.chunk_index),
                status: entry.status,
                message: entry.message,
            }).collect())
        }
        ContainerKind::L01 => Err("L01 verification is not implemented yet.".to_string()),
        ContainerKind::Raw => {
            let computed_hash = raw::verify(path, algorithm)?;
            Ok(vec![VerifyEntry {
                path: None,
                chunk_index: None,
                status: "computed".to_string(),
                message: Some(format!("{}: {}", algorithm.to_uppercase(), computed_hash)),
            }])
        }
        ContainerKind::Archive => Err("Archive verification is not implemented yet. Use standard archive tools.".to_string()),
    }
}

pub fn extract(path: &str, output_dir: &str) -> Result<(), String> {
    match detect_container(path)? {
        ContainerKind::Ad1 => ad1::extract(path, output_dir),
        ContainerKind::E01 => ewf::extract(path, output_dir),
        ContainerKind::L01 => Err("L01 extraction is not implemented yet.".to_string()),
        ContainerKind::Raw => raw::extract(path, output_dir),
        ContainerKind::Archive => Err("Archive extraction is not implemented yet. Use standard archive tools (7z, unzip).".to_string()),
    }
}

fn detect_container(path: &str) -> Result<ContainerKind, String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("Input file not found: {path}"));
    }

    let lower = path.to_lowercase();
    
    // Check E01/EWF first (before L01 to avoid .lx01 confusion)
    // Support .e01, .ex01, .e02, .e03, etc., and .ewf extensions
    if lower.ends_with(".e01") || lower.ends_with(".ex01") || lower.ends_with(".ewf") 
        || lower.contains(".e0") || lower.contains(".ex")
    {
        debug!("Checking E01 signature for: {}", path);
        if ewf::is_e01(path).unwrap_or(false) {
            return Ok(ContainerKind::E01);
        } else {
            debug!("E01 signature check failed for: {}", path);
        }
    }
    
    // Check L01
    if (lower.ends_with(".l01") || lower.ends_with(".lx01"))
        && l01::is_l01(path).unwrap_or(false) 
    {
        return Ok(ContainerKind::L01);
    }

    // Check AD1
    if ad1::is_ad1(path)? {
        return Ok(ContainerKind::Ad1);
    }

    // Check archive formats (7z, ZIP, RAR, etc.) - before raw to catch .7z.001 properly
    if archive::is_archive(path).unwrap_or(false) {
        return Ok(ContainerKind::Archive);
    }

    // Check raw disk images (.dd, .raw, .img, .001, .002, etc.)
    if raw::is_raw(path).unwrap_or(false) {
        return Ok(ContainerKind::Raw);
    }

    Err(format!("Unsupported or unrecognized logical container: {}\nSupported formats: AD1, E01/EWF, L01, RAW (.dd, .raw, .img, .001), Archives (7z, ZIP, RAR)", path))
}

pub fn scan_directory(dir_path: &str) -> Result<Vec<DiscoveredFile>, String> {
    scan_directory_impl(dir_path, false)
}

pub fn scan_directory_recursive(dir_path: &str) -> Result<Vec<DiscoveredFile>, String> {
    scan_directory_impl(dir_path, true)
}

/// Streaming scan that calls callback for each file found (for real-time UI updates)
pub fn scan_directory_streaming<F>(dir_path: &str, recursive: bool, on_file_found: F) -> Result<usize, String>
where
    F: Fn(&DiscoveredFile),
{
    let path = Path::new(dir_path);
    if !path.exists() {
        return Err(format!("Directory not found: {dir_path}"));
    }
    if !path.is_dir() {
        return Err(format!("Path is not a directory: {dir_path}"));
    }

    let mut seen_basenames = std::collections::HashSet::new();
    let mut count = 0;

    scan_dir_streaming_internal(path, &mut seen_basenames, recursive, &on_file_found, &mut count)?;

    Ok(count)
}

fn scan_dir_streaming_internal<F>(
    path: &Path,
    seen_basenames: &mut std::collections::HashSet<String>,
    recursive: bool,
    on_file_found: &F,
    count: &mut usize,
) -> Result<(), String>
where
    F: Fn(&DiscoveredFile),
{
    let entries = fs::read_dir(path)
        .map_err(|e| format!("Failed to read directory: {e}"))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let entry_path = entry.path();
        
        // Use file_type() from DirEntry - more reliable than path.is_dir()
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        
        // Recurse into subdirectories if enabled
        if recursive && file_type.is_dir() {
            let _ = scan_dir_streaming_internal(&entry_path, seen_basenames, recursive, on_file_found, count);
            continue;
        }
        
        if !file_type.is_file() {
            continue;
        }

        let path_str = match entry_path.to_str() {
            Some(s) => s,
            None => continue,
        };

        let filename = entry
            .file_name()
            .to_string_lossy()
            .to_string();

        // Skip macOS resource fork files (._filename)
        if filename.starts_with("._") {
            continue;
        }

        let lower = filename.to_lowercase();
        
        // Skip non-first segments entirely - we only want to show one entry per container
        if !is_first_segment(&lower) {
            continue;
        }
        
        // Check for forensic container files by extension only (fast, no file I/O)
        // Validation of actual file format happens later in logical_info
        let container_type = if lower.ends_with(".ad1") {
            Some("AD1")
        } else if lower.ends_with(".l01") {
            Some("L01")
        } else if lower.ends_with(".lx01") {
            Some("Lx01")
        } else if lower.ends_with(".tar") {
            if lower.contains("logical") {
                Some("TAR (Logical)")
            } else {
                Some("TAR")
            }
        } else if lower.ends_with(".e01") {
            Some("EnCase (E01)")
        } else if lower.ends_with(".ex01") {
            Some("EnCase (Ex01)")
        } else if lower.ends_with(".aff") || lower.ends_with(".afd") {
            Some("AFF")
        // Archive formats - check before raw to catch .7z.001 properly
        } else if lower.ends_with(".7z") || lower.ends_with(".7z.001") {
            Some("7-Zip")
        } else if lower.ends_with(".zip") || lower.ends_with(".zip.001") || lower.ends_with(".z01") {
            Some("ZIP")
        } else if lower.ends_with(".rar") || lower.ends_with(".r00") {
            Some("RAR")
        } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
            Some("TAR.GZ")
        } else if lower.ends_with(".gz") && !lower.ends_with(".tar.gz") {
            Some("GZIP")
        } else if is_numbered_segment(&lower) && !is_archive_segment(&lower) {
            // Raw image segments (.001, .002, etc.) - but not archive segments
            Some("Raw Image")
        } else if lower.ends_with(".dd") || lower.ends_with(".raw") || lower.ends_with(".img") {
            Some("Raw Image")
        } else {
            None
        };

        if let Some(ctype) = container_type {
            // For multi-segment files (like .E01, .001), only show the first segment
            let basename = get_segment_basename(&filename);
            if seen_basenames.insert(basename.clone()) {
                // For numbered segments, construct .001 path without checking existence (fast)
                let display_path = if is_numbered_segment(&lower) {
                    get_first_segment_path_fast(path_str)
                } else {
                    path_str.to_string()
                };
                
                let display_filename = Path::new(&display_path)
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or(filename.clone());
                
                // Use DirEntry metadata (cached from readdir syscall) - fast
                let metadata = entry.metadata().ok();
                let file_size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                
                // FAST PATH: Skip segment calculation during scan - it's slow on external drives
                // Segment details will be calculated on-demand when user selects a file
                // Just use the first file's size for now
                
                // Skip timestamps during scan - they're slow and rarely needed
                let file = DiscoveredFile {
                    path: display_path,
                    filename: display_filename,
                    container_type: ctype.to_string(),
                    size: file_size, // Just first segment size - full size calculated on-demand
                    segment_count: None,
                    segment_files: None,
                    segment_sizes: None,
                    total_segment_size: None,
                    created: None,
                    modified: None,
                };
                
                on_file_found(&file);
                *count += 1;
            }
        }
    }

    Ok(())
}

fn scan_directory_impl(dir_path: &str, recursive: bool) -> Result<Vec<DiscoveredFile>, String> {
    let path = Path::new(dir_path);
    if !path.exists() {
        return Err(format!("Directory not found: {dir_path}"));
    }
    if !path.is_dir() {
        return Err(format!("Path is not a directory: {dir_path}"));
    }

    let mut discovered = Vec::new();
    let mut seen_basenames = std::collections::HashSet::new();

    scan_dir_internal(path, &mut discovered, &mut seen_basenames, recursive)?;

    Ok(discovered)
}

fn scan_dir_internal(
    path: &Path,
    discovered: &mut Vec<DiscoveredFile>,
    seen_basenames: &mut std::collections::HashSet<String>,
    recursive: bool,
) -> Result<(), String> {
    let entries = fs::read_dir(path)
        .map_err(|e| format!("Failed to read directory: {e}"))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let entry_path = entry.path();
        
        // Use file_type() from DirEntry - more reliable than path.is_dir()
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        
        // Recurse into subdirectories if enabled
        if recursive && file_type.is_dir() {
            let _ = scan_dir_internal(&entry_path, discovered, seen_basenames, recursive);
            continue;
        }
        
        if !file_type.is_file() {
            continue;
        }

        let path_str = match entry_path.to_str() {
            Some(s) => s,
            None => continue,
        };

        let filename = entry
            .file_name()
            .to_string_lossy()
            .to_string();

        // Skip macOS resource fork files (._filename)
        if filename.starts_with("._") {
            continue;
        }

        let lower = filename.to_lowercase();
        
        // Skip non-first segments entirely - we only want to show one entry per container
        if !is_first_segment(&lower) {
            continue;
        }
        
        // Check for forensic container files
        let container_type = if lower.ends_with(".ad1") {
            // Verify it's actually an AD1 file
            match ad1::is_ad1(path_str) {
                Ok(true) => Some("AD1"),
                _ => None,
            }
        } else if lower.ends_with(".l01") {
            Some("L01")
        } else if lower.ends_with(".lx01") {
            Some("Lx01")
        } else if lower.ends_with(".tar") {
            // Check for logical extraction archives (e.g., "Google Pixel 3a XL Logical Image - Data.tar")
            if lower.contains("logical") {
                Some("TAR (Logical)")
            } else {
                Some("TAR")
            }
        } else if lower.ends_with(".e01") {
            // E01 files are EnCase
            Some("EnCase (E01)")
        } else if is_numbered_segment(&lower) {
            // Numbered segments (.001, .002, etc.) - check if EnCase or Raw
            // Find the first segment (.001) to check magic bytes
            let first_seg_path = get_first_segment_path(path_str);
            if ewf::is_e01(&first_seg_path).unwrap_or(false) {
                Some("EnCase (E01)")
            } else if raw::is_raw(&first_seg_path).unwrap_or(false) {
                Some("Raw Image")
            } else {
                // Default to raw for unknown numbered segments
                Some("Raw Image")
            }
        } else if lower.ends_with(".ex01") {
            Some("EnCase (Ex01)")
        } else if lower.ends_with(".aff") || lower.ends_with(".afd") {
            Some("AFF")
        } else if lower.ends_with(".dd") || lower.ends_with(".raw") || lower.ends_with(".img") {
            Some("Raw Image")
        } else {
            None
        };

        if let Some(ctype) = container_type {
            // For multi-segment files (like .E01, .001), only show the first segment
            let basename = get_segment_basename(&filename);
            if seen_basenames.insert(basename.clone()) {
                // For numbered segments, always use the first segment path (.001)
                let display_path = if is_numbered_segment(&lower) {
                    get_first_segment_path(path_str)
                } else {
                    path_str.to_string()
                };
                
                let display_filename = Path::new(&display_path)
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or(filename.clone());
                
                let metadata = entry.metadata().ok();
                let file_size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                
                // Get file creation time (birth time on macOS/Windows, fall back to modified)
                let created = metadata.as_ref().and_then(|m| {
                    m.created().ok()
                        .map(|t| {
                            let datetime: chrono::DateTime<chrono::Utc> = t.into();
                            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
                        })
                });
                
                // Get file modified time
                let modified = metadata.as_ref().and_then(|m| {
                    m.modified().ok()
                        .map(|t| {
                            let datetime: chrono::DateTime<chrono::Utc> = t.into();
                            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
                        })
                });

                // FAST PATH: Skip segment calculation during scan - it's slow on external drives
                // Segment details will be calculated on-demand when user selects a file

                discovered.push(DiscoveredFile {
                    path: display_path,
                    filename: display_filename,
                    container_type: ctype.to_string(),
                    size: file_size, // Just first segment size - full size calculated on-demand
                    segment_count: None,
                    segment_files: None,
                    segment_sizes: None,
                    total_segment_size: None,
                    created,
                    modified,
                });
            }
        }
    }

    Ok(())
}

/// Check if filename is a numbered segment (.001, .002, etc.)
fn is_numbered_segment(lower: &str) -> bool {
    if let Some(ext_start) = lower.rfind('.') {
        let ext = &lower[ext_start + 1..];
        if ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    false
}

/// Get the path to the first available segment given any segment path
/// Tries .001 first, then scans for the lowest numbered segment
fn get_first_segment_path(path: &str) -> String {
    let path_obj = Path::new(path);
    if let Some(parent) = path_obj.parent() {
        if let Some(filename) = path_obj.file_name() {
            let filename_str = filename.to_string_lossy();
            if let Some(dot_pos) = filename_str.rfind('.') {
                let base = &filename_str[..dot_pos];
                
                // Try .001 first (most common)
                let first_seg = format!("{}.001", base);
                let first_path = parent.join(&first_seg);
                if first_path.exists() {
                    return first_path.to_string_lossy().to_string();
                }
                
                // If .001 doesn't exist, find the lowest numbered segment
                for num in 2..=999 {
                    let seg_name = format!("{}.{:03}", base, num);
                    let seg_path = parent.join(&seg_name);
                    if seg_path.exists() {
                        return seg_path.to_string_lossy().to_string();
                    }
                }
            }
        }
    }
    // Return original path if we can't find any lower segment
    path.to_string()
}

/// Fast version - just constructs .001 path without checking existence
/// Used during directory scan to avoid slow file I/O
fn get_first_segment_path_fast(path: &str) -> String {
    let path_obj = Path::new(path);
    if let Some(parent) = path_obj.parent() {
        if let Some(filename) = path_obj.file_name() {
            let filename_str = filename.to_string_lossy();
            if let Some(dot_pos) = filename_str.rfind('.') {
                let base = &filename_str[..dot_pos];
                let first_seg = format!("{}.001", base);
                return parent.join(&first_seg).to_string_lossy().to_string();
            }
        }
    }
    path.to_string()
}

/// Check if file is part of a segmented series
#[allow(dead_code)]
fn is_segmented_file(lower: &str) -> bool {
    lower.ends_with(".e01") || lower.ends_with(".e02") || lower.ends_with(".ex01") || 
    is_numbered_segment(lower) || is_ad1_segment(lower)
}

/// Check if filename is an AD1 segment (.ad1, .ad2, .ad3, etc.)
fn is_ad1_segment(lower: &str) -> bool {
    if lower.len() < 4 { return false; }
    if let Some(dot_pos) = lower.rfind('.') {
        let ext = &lower[dot_pos + 1..];
        if ext.starts_with("ad") && ext.len() >= 3 {
            let num_part = &ext[2..];
            return num_part.chars().all(|c| c.is_ascii_digit()) && !num_part.is_empty();
        }
    }
    false
}

/// Check if this is the first segment of a multi-segment file
fn is_first_segment(lower: &str) -> bool {
    // AD1 files: .ad1 is first
    if lower.ends_with(".ad1") { return true; }
    // AD1 segments but not first: .ad2, .ad3, etc.
    if is_ad1_segment(lower) && !lower.ends_with(".ad1") { return false; }
    
    // E01 files: .E01 is first
    if lower.ends_with(".e01") { return true; }
    // E01 segments but not first
    if lower.ends_with(".e02") { return false; }
    for i in 3..=99 {
        if lower.ends_with(&format!(".e{:02}", i)) { return false; }
    }
    
    // Archive formats - first segments
    // 7z: .7z or .7z.001 is first
    if lower.ends_with(".7z") { return true; }
    if lower.ends_with(".7z.001") { return true; }
    // .7z.002, .7z.003, etc. are not first
    if is_7z_continuation(lower) { return false; }
    
    // ZIP: .zip or .zip.001 or .z01 is first
    if lower.ends_with(".zip") { return true; }
    if lower.ends_with(".zip.001") { return true; }
    if lower.ends_with(".z01") { return true; }
    // .zip.002, .z02, etc. are not first
    if is_zip_continuation(lower) { return false; }
    
    // RAR: .rar or .r00 is first
    if lower.ends_with(".rar") { return true; }
    if lower.ends_with(".r00") { return true; }
    // .r01, .r02, etc. are not first
    if is_rar_continuation(lower) { return false; }
    
    // TAR archives
    if lower.ends_with(".tar") || lower.ends_with(".tar.gz") || lower.ends_with(".tgz") { return true; }
    
    // GZIP
    if lower.ends_with(".gz") { return true; }
    
    // Numbered segments: .001 is first (for non-archive files)
    if let Some(dot_pos) = lower.rfind('.') {
        let ext = &lower[dot_pos + 1..];
        if ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()) {
            return ext == "001";
        }
    }
    
    // Not a segment file, treat as first
    true
}

/// Check if this is a 7z continuation segment (.7z.002, .7z.003, etc.)
fn is_7z_continuation(lower: &str) -> bool {
    if let Some(pos) = lower.rfind(".7z.") {
        let suffix = &lower[pos + 4..];
        if suffix.chars().all(|c| c.is_ascii_digit()) && suffix != "001" {
            return true;
        }
    }
    false
}

/// Check if this is a ZIP continuation segment (.zip.002, .z02, etc.)
fn is_zip_continuation(lower: &str) -> bool {
    // .zip.002, .zip.003, etc.
    if let Some(pos) = lower.rfind(".zip.") {
        let suffix = &lower[pos + 5..];
        if suffix.chars().all(|c| c.is_ascii_digit()) && suffix != "001" {
            return true;
        }
    }
    // .z02, .z03, etc.
    if lower.len() >= 4 {
        let ext = &lower[lower.len() - 4..];
        if ext.starts_with(".z") && ext[2..].chars().all(|c| c.is_ascii_digit()) && ext != ".z01" {
            return true;
        }
    }
    false
}

/// Check if this is a RAR continuation segment (.r01, .r02, etc.)
fn is_rar_continuation(lower: &str) -> bool {
    if lower.len() >= 4 {
        let ext = &lower[lower.len() - 4..];
        if ext.starts_with(".r") && ext[2..].chars().all(|c| c.is_ascii_digit()) && ext != ".r00" {
            return true;
        }
    }
    false
}

/// Check if this is an archive segment (any type)
fn is_archive_segment(lower: &str) -> bool {
    is_7z_continuation(lower) || is_zip_continuation(lower) || is_rar_continuation(lower)
        || lower.ends_with(".7z.001")
        || lower.ends_with(".zip.001")
}

/// Get the base name without segment number for grouping
fn get_segment_basename(filename: &str) -> String {
    let lower = filename.to_lowercase();
    
    // Handle .E01, .E02, etc.
    if lower.ends_with(".e01") {
        return filename[..filename.len() - 4].to_string();
    }
    
    // Handle .ad1, .ad2, .ad3, etc.
    if is_ad1_segment(&lower) {
        if let Some(dot_pos) = filename.rfind('.') {
            return filename[..dot_pos].to_string();
        }
    }
    
    // Handle .7z.001, .7z.002, etc.
    if let Some(pos) = lower.rfind(".7z.") {
        return filename[..pos + 3].to_string(); // Keep .7z
    }
    
    // Handle .zip.001, .zip.002, etc.
    if let Some(pos) = lower.rfind(".zip.") {
        return filename[..pos + 4].to_string(); // Keep .zip
    }
    
    // Handle .z01, .z02, etc. (ZIP split)
    if lower.len() >= 4 {
        let ext = &lower[lower.len() - 4..];
        if ext.starts_with(".z") && ext[2..].chars().all(|c| c.is_ascii_digit()) {
            return filename[..filename.len() - 4].to_string();
        }
    }
    
    // Handle .r00, .r01, etc. (RAR segments)
    if lower.len() >= 4 {
        let ext = &lower[lower.len() - 4..];
        if ext.starts_with(".r") && ext[2..].chars().all(|c| c.is_ascii_digit()) {
            return filename[..filename.len() - 4].to_string();
        }
    }
    
    // Handle .001, .002, etc.
    if let Some(dot_pos) = filename.rfind('.') {
        let ext = &filename[dot_pos + 1..];
        if ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()) {
            return filename[..dot_pos].to_string();
        }
    }
    
    filename.to_string()
}

/// Detailed segment information
#[allow(dead_code)]
struct SegmentInfo {
    total_size: u64,
    count: u32,
    files: Vec<String>,
    sizes: Vec<u64>,
}

/// Calculate total size of all segments in a series
#[allow(dead_code)]
fn calculate_total_segment_info(dir: &Path, basename: &str) -> Option<SegmentInfo> {
    let mut total = 0u64;
    let mut count = 0u32;
    let mut files = Vec::new();
    let mut sizes = Vec::new();
    
    // Try AD1 segments first (.ad1, .ad2, .ad3, ...)
    for i in 1..=100 {
        let segment_name = format!("{}.ad{}", basename, i);
        let segment_path = dir.join(&segment_name);
        if let Ok(metadata) = segment_path.metadata() {
            let size = metadata.len();
            total += size;
            count += 1;
            files.push(segment_name);
            sizes.push(size);
        } else {
            break;
        }
    }
    
    if total > 0 {
        return Some(SegmentInfo { total_size: total, count, files, sizes });
    }
    
    // Try E01 segments (.E01, .E02, ...)
    for segment_num in 1..=100 {
        let segment_name = if segment_num == 1 {
            format!("{}.E01", basename)
        } else {
            format!("{}.E{:02}", basename, segment_num)
        };
        
        let segment_path = dir.join(&segment_name);
        if let Ok(metadata) = segment_path.metadata() {
            let size = metadata.len();
            total += size;
            count += 1;
            files.push(segment_name);
            sizes.push(size);
        } else {
            break;
        }
    }
    
    if total > 0 {
        return Some(SegmentInfo { total_size: total, count, files, sizes });
    }
    
    // Try numbered segments (.001, .002, ...)
    for segment_num in 1..=999 {
        let segment_name = format!("{}.{:03}", basename, segment_num);
        let segment_path = dir.join(&segment_name);
        if let Ok(metadata) = segment_path.metadata() {
            let size = metadata.len();
            total += size;
            count += 1;
            files.push(segment_name);
            sizes.push(size);
        } else {
            break;
        }
    }
    
    if total > 0 {
        return Some(SegmentInfo { total_size: total, count, files, sizes });
    }
    
    None
}

/// Find and parse companion log file (e.g., .txt file created by FTK Imager, dc3dd, etc.)
fn find_companion_log(image_path: &str) -> Option<CompanionLogInfo> {
    debug!("Looking for companion log for: {}", image_path);
    let path = Path::new(image_path);
    let parent = path.parent()?;
    let stem = path.file_stem()?.to_str()?;
    let filename = path.file_name()?.to_str()?;
    
    // For segmented raw images (.001, .002), get the base name without segment number
    let base_stem = if let Some(dot_pos) = stem.rfind('.') {
        let ext = &stem[dot_pos + 1..];
        if ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()) {
            // This is like "image.001" where stem is "image"
            stem.to_string()
        } else {
            stem.to_string()
        }
    } else {
        stem.to_string()
    };
    
    // Also handle case where filename is "image.001" - stem would be "image"
    // But if filename is "image.dd.001" - stem would be "image.dd"
    let numeric_ext = filename.rsplit('.').next()
        .map(|e| e.len() == 3 && e.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false);
    
    let base_for_log = if numeric_ext {
        // Remove numeric extension from filename for log search
        &filename[..filename.len() - 4]
    } else {
        filename
    };
    
    // Common companion log file patterns for various forensic tools:
    let mut candidate_paths = vec![
        // Standard patterns
        parent.join(format!("{}.txt", filename)),           // image.ad1.txt, image.dd.txt
        parent.join(format!("{}.txt", stem)),               // image.txt
        parent.join(format!("{}_info.txt", stem)),          // image_info.txt
        parent.join(format!("{}.log", filename)),           // image.ad1.log
        parent.join(format!("{}.log", stem)),               // image.log
        parent.join(format!("{}.LOG", stem)),               // image.LOG (uppercase for Forensic MD5)
        
        // AD1 / FTK Imager specific patterns
        parent.join(format!("{}.ad1.txt", stem)),           // image.ad1.txt (FTK Imager)
        parent.join(format!("{}1.txt", stem)),              // image1.txt (if stem ends in number)
        parent.join(format!("{}_img1.ad1.txt", stem.trim_end_matches("_img1"))), // For _img1 suffix
        
        // E01 / EnCase specific patterns  
        parent.join(format!("{}.E01.txt", stem)),           // image.E01.txt
        parent.join(format!("{}.e01.txt", stem)),           // image.e01.txt
        
        // For segmented raw images
        parent.join(format!("{}.txt", base_for_log)),       // image.dd.txt for image.dd.001
        parent.join(format!("{}.log", base_for_log)),       // image.dd.log for image.dd.001
        parent.join(format!("{}.LOG", base_for_log)),       // image.dd.LOG for image.dd.001
        parent.join(format!("{}_info.txt", base_for_log)),  // image.dd_info.txt
        
        // dc3dd / dcfldd patterns
        parent.join(format!("{}.hash", stem)),              // image.hash
        parent.join(format!("{}.md5", stem)),               // image.md5
        parent.join(format!("{}.sha1", stem)),              // image.sha1
        parent.join(format!("{}.sha256", stem)),            // image.sha256
        parent.join(format!("{}_hash.txt", stem)),          // image_hash.txt
        parent.join(format!("{}_hashes.txt", stem)),        // image_hashes.txt
        
        // Guymager patterns
        parent.join(format!("{}.info", stem)),              // image.info
        parent.join(format!("{}.info", filename)),          // image.dd.info
        
        // MacQuisition / Paladin / other tools
        parent.join(format!("{}_acquisition.txt", stem)),   // image_acquisition.txt
        parent.join(format!("{}_acquisition.log", stem)),   // image_acquisition.log
    ];
    
    // Also try with base_stem for segmented images
    if base_stem != stem {
        candidate_paths.push(parent.join(format!("{}.txt", base_stem)));
        candidate_paths.push(parent.join(format!("{}.log", base_stem)));
        candidate_paths.push(parent.join(format!("{}.LOG", base_stem)));  // SCHARDT.LOG
        candidate_paths.push(parent.join(format!("{}_info.txt", base_stem)));
    }
    
    for log_path in candidate_paths {
        if log_path.exists() {
            debug!("Found companion log candidate: {:?}", log_path);
            if let Ok(info) = parse_companion_log(&log_path) {
                debug!("Successfully parsed companion log: {:?}", log_path);
                return Some(info);
            }
        }
    }
    
    debug!("No companion log found for: {}", image_path);
    None
}

/// Parse companion log file from various forensic tools (FTK Imager, dc3dd, dcfldd, Guymager, etc.)
fn parse_companion_log(log_path: &Path) -> Result<CompanionLogInfo, String> {
    let content = fs::read_to_string(log_path)
        .map_err(|e| format!("Failed to read log file: {}", e))?;
    
    let mut info = CompanionLogInfo {
        log_path: log_path.to_string_lossy().to_string(),
        created_by: None,
        case_number: None,
        evidence_number: None,
        unique_description: None,
        examiner: None,
        notes: None,
        acquisition_started: None,
        acquisition_finished: None,
        verification_started: None,
        verification_finished: None,
        stored_hashes: Vec::new(),
        segment_list: Vec::new(),
        segment_hashes: Vec::new(),
    };
    
    // Detect file format based on content
    let content_lower = content.to_lowercase();
    let is_dc3dd = content_lower.contains("dc3dd") || content_lower.contains("dcfldd");
    let is_guymager = content_lower.contains("guymager");
    let is_forensic_md5 = content_lower.contains("forensic md5") || 
                          content.contains("MD5 Value:") ||
                          content.lines().any(|l| l.trim().starts_with("* ") && l.contains("From:") && l.contains("To:"));
    let is_hash_only = log_path.extension()
        .map(|e| matches!(e.to_str(), Some("md5" | "sha1" | "sha256" | "hash")))
        .unwrap_or(false);
    
    // Handle hash-only files (just hash value, maybe with filename)
    if is_hash_only {
        if let Some(hash_info) = parse_simple_hash_file(&content, log_path) {
            info.stored_hashes.push(hash_info);
            return Ok(info);
        }
    }
    
    // Handle Forensic MD5 per-segment hash format
    if is_forensic_md5 {
        if let Some(segment_hashes) = parse_forensic_md5_segments(&content) {
            info.segment_hashes = segment_hashes;
            info.created_by = Some("Forensic MD5".to_string());
        }
    }
    
    // Parse line by line
    let mut in_segment_list = false;
    let mut in_computed_hashes = false;
    let mut in_verification_results = false;
    
    for line in content.lines() {
        let line = line.trim();
        let line_lower = line.to_lowercase();
        
        // Skip empty lines
        if line.is_empty() {
            continue;
        }
        
        // Check for section headers
        if line.starts_with("Created By ") || line_lower.starts_with("created by:") {
            let value = line.split_once(':').or(line.split_once(' '))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_else(|| line.to_string());
            if !value.is_empty() && value != "By" {
                info.created_by = Some(value);
            }
            continue;
        }
        
        // dc3dd/dcfldd output parsing
        if is_dc3dd {
            // Patterns like "md5 hash: abc123..." or "sha256: abc123..."
            if let Some(hash_info) = parse_dc3dd_hash_line(line) {
                info.stored_hashes.push(hash_info);
                continue;
            }
            
            // Input/output device info
            if line_lower.starts_with("input device:") || line_lower.starts_with("input:") {
                if let Some((_, v)) = line.split_once(':') {
                    info.unique_description = Some(v.trim().to_string());
                }
                continue;
            }
        }
        
        // Guymager output parsing
        if is_guymager {
            if let Some(hash_info) = parse_guymager_hash_line(line) {
                info.stored_hashes.push(hash_info);
                continue;
            }
        }
        
        if line == "Segment list:" || line == "[Segment List]" {
            in_segment_list = true;
            in_computed_hashes = false;
            in_verification_results = false;
            continue;
        }
        
        if line.starts_with("[Computed Hashes]") || line == "Computed Hashes:" {
            in_computed_hashes = true;
            in_segment_list = false;
            in_verification_results = false;
            continue;
        }
        
        if line.starts_with("Image Verification Results:") || line == "[Verification Results]" {
            in_verification_results = true;
            in_segment_list = false;
            in_computed_hashes = false;
            continue;
        }
        
        // Parse segment list entries
        if in_segment_list && !line.is_empty() && !line.starts_with("Image") && !line.starts_with("[") {
            info.segment_list.push(line.to_string());
            continue;
        }
        
        // Parse hash entries (both computed and verification)
        if in_computed_hashes || in_verification_results {
            if let Some(hash_info) = parse_hash_line(line, in_verification_results) {
                // Check if we already have this algorithm - update with verification status
                if let Some(existing) = info.stored_hashes.iter_mut()
                    .find(|h| h.algorithm.to_lowercase() == hash_info.algorithm.to_lowercase()) 
                {
                    if hash_info.verified.is_some() {
                        existing.verified = hash_info.verified;
                    }
                } else {
                    info.stored_hashes.push(hash_info);
                }
                continue;
            }
        }
        
        // Parse key-value pairs
        if let Some((key, value)) = parse_key_value(line) {
            match key.to_lowercase().as_str() {
                "case number" | "case" | "case_number" => info.case_number = Some(value),
                "evidence number" | "evidence" | "evidence_number" => info.evidence_number = Some(value),
                "unique description" | "description" => info.unique_description = Some(value),
                "examiner" | "examiner name" => info.examiner = Some(value),
                "notes" | "note" | "comments" => info.notes = Some(value),
                "acquisition started" | "start time" | "started" => info.acquisition_started = Some(value),
                "acquisition finished" | "end time" | "finished" | "completed" => info.acquisition_finished = Some(value),
                "verification started" => info.verification_started = Some(value),
                "verification finished" => info.verification_finished = Some(value),
                "source" | "source device" | "input" => {
                    if info.unique_description.is_none() {
                        info.unique_description = Some(value);
                    }
                }
                "tool" | "program" | "software" => {
                    if info.created_by.is_none() {
                        info.created_by = Some(value);
                    }
                }
                _ => {
                    // Check if this looks like a hash line
                    if let Some(hash_info) = parse_hash_line(line, false) {
                        info.stored_hashes.push(hash_info);
                    }
                }
            }
        }
    }
    
    // Only return if we found useful information
    if info.stored_hashes.is_empty() 
        && info.case_number.is_none() 
        && info.evidence_number.is_none()
        && info.examiner.is_none()
        && info.created_by.is_none()
        && info.unique_description.is_none()
        && info.segment_list.is_empty()
        && info.segment_hashes.is_empty()
    {
        return Err("No useful information found in log file".to_string());
    }
    
    Ok(info)
}

/// Parse a simple hash file (just hash value, possibly with filename)
fn parse_simple_hash_file(content: &str, log_path: &Path) -> Option<StoredHash> {
    let ext = log_path.extension()?.to_str()?.to_lowercase();
    let algorithm = match ext.as_str() {
        "md5" => "MD5",
        "sha1" => "SHA-1",
        "sha256" => "SHA-256",
        "sha512" => "SHA-512",
        "hash" => return parse_hash_from_content(content, log_path),
        _ => return None,
    };
    
    // Extract hash from content (might be "hash  filename" or just "hash")
    let re = Regex::new(r"[a-fA-F0-9]{32,128}").ok()?;
    let hash = re.find(content.trim())?.as_str().to_lowercase();
    
    // Get file modification time as timestamp
    let timestamp = log_path.metadata().ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let datetime: chrono::DateTime<chrono::Utc> = t.into();
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        });
    
    Some(StoredHash {
        algorithm: algorithm.to_string(),
        hash,
        verified: None,
        timestamp,
        source: Some("companion".to_string()),
    })
}

/// Parse hash from generic hash file content
fn parse_hash_from_content(content: &str, log_path: &Path) -> Option<StoredHash> {
    let re = Regex::new(r"[a-fA-F0-9]{32,128}").ok()?;
    let hash = re.find(content.trim())?.as_str().to_lowercase();
    
    // Guess algorithm from hash length
    let algorithm = match hash.len() {
        32 => "MD5",
        40 => "SHA-1",
        64 => "SHA-256",
        128 => "SHA-512",
        _ => return None,
    };
    
    // Get file modification time as timestamp
    let timestamp = log_path.metadata().ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let datetime: chrono::DateTime<chrono::Utc> = t.into();
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        });
    
    Some(StoredHash {
        algorithm: algorithm.to_string(),
        hash,
        verified: None,
        timestamp,
        source: Some("companion".to_string()),
    })
}

/// Parse dc3dd/dcfldd style hash output
fn parse_dc3dd_hash_line(line: &str) -> Option<StoredHash> {
    let line_lower = line.to_lowercase();
    
    // Patterns:
    // "md5 hash: abc123..."
    // "sha256 hash of input: abc123..."
    // "abc123... (md5)"
    
    let algorithms = [
        ("md5", "MD5"),
        ("sha1", "SHA-1"),
        ("sha-1", "SHA-1"),
        ("sha256", "SHA-256"),
        ("sha-256", "SHA-256"),
        ("sha512", "SHA-512"),
        ("sha-512", "SHA-512"),
    ];
    
    for (pattern, algo_name) in &algorithms {
        if line_lower.contains(pattern) {
            if let Some(m) = hash_regex().find(line) {
                return Some(StoredHash {
                    algorithm: algo_name.to_string(),
                    hash: m.as_str().to_lowercase(),
                    verified: None,
                    timestamp: None,  // Will be set by caller from log file context
                    source: Some("companion".to_string()),
                });
            }
        }
    }
    
    None
}

/// Parse Guymager style hash output
fn parse_guymager_hash_line(line: &str) -> Option<StoredHash> {
    // Guymager patterns:
    // "MD5 hash verified source: abc123..."
    // "SHA-256 hash: abc123..."
    parse_dc3dd_hash_line(line)  // Same pattern matching works
}

/// Parse a hash line from the log file
fn parse_hash_line(line: &str, check_verified: bool) -> Option<StoredHash> {
    let line_lower = line.to_lowercase();
    
    // Common patterns:
    // "MD5 checksum:    e0778ff7fb490fc2c9c56824f9ecf448"
    // "SHA1 checksum:   93d522376d89b8dfe6bb61e4abef2bbb7102765a"
    // "MD5 checksum:    e0778ff7fb490fc2c9c56824f9ecf448 : verified"
    // "MD5: e0778ff7fb490fc2c9c56824f9ecf448"
    
    let algorithms = ["md5", "sha1", "sha256", "sha512", "sha-1", "sha-256", "sha-512"];
    
    for alg in &algorithms {
        if line_lower.contains(alg) {
            // Try to extract the hash value using pre-compiled regex
            if let Some(m) = hash_regex().find(line) {
                let hash = m.as_str().to_lowercase();
                
                // Check for verification status
                let verified = if check_verified {
                    if line_lower.contains(": verified") || line_lower.contains("verified") {
                        Some(true)
                    } else if line_lower.contains(": failed") || line_lower.contains("mismatch") {
                        Some(false)
                    } else {
                        None
                    }
                } else {
                    None
                };
                
                let algo_name = match *alg {
                    "md5" => "MD5",
                    "sha1" | "sha-1" => "SHA-1",
                    "sha256" | "sha-256" => "SHA-256",
                    "sha512" | "sha-512" => "SHA-512",
                    _ => *alg,
                };
                
                return Some(StoredHash {
                    algorithm: algo_name.to_string(),
                    hash,
                    verified,
                    timestamp: None,  // Will be set by caller from log file context
                    source: Some("companion".to_string()),
                });
            }
        }
    }
    
    None
}

/// Parse a key: value line
fn parse_key_value(line: &str) -> Option<(String, String)> {
    // Match patterns like "Case Number: 12345" or "Examiner:  John Doe"
    if let Some(colon_pos) = line.find(':') {
        let key = line[..colon_pos].trim();
        let value = line[colon_pos + 1..].trim();
        if !key.is_empty() && !value.is_empty() {
            return Some((key.to_string(), value.to_string()));
        }
    }
    None
}

/// Parse "Forensic MD5" style per-segment hash log files
/// Format:
/// * SCHARDT.001: From: 0, To: 1389747, Size: 1301248, MD5 Value:
/// * ...28A9B613 D6EEFE8A 0515EF0A 675BDEBD...
fn parse_forensic_md5_segments(content: &str) -> Option<Vec<SegmentHash>> {
    let mut segments: Vec<SegmentHash> = Vec::new();
    let mut current_segment: Option<SegmentHash> = None;
    
    for line in content.lines() {
        let line = line.trim();
        
        // Skip empty lines
        if line.is_empty() {
            continue;
        }
        
        // Look for segment header: "* SEGMENT.XXX: From: X, To: Y, Size: Z, MD5 Value:"
        if line.starts_with("* ") && line.contains(": From:") {
            // Save previous segment if any
            if let Some(seg) = current_segment.take() {
                if !seg.hash.is_empty() {
                    segments.push(seg);
                }
            }
            
            // Parse the segment header
            // Format: "* SCHARDT.001: From: 0, To: 1389747, Size: 1301248, MD5 Value:"
            let inner = &line[2..]; // Skip "* "
            
            // Extract segment name (before first ':')
            let segment_name = inner.split(':').next()?.trim().to_string();
            
            // Extract segment number from name
            let segment_number = extract_segment_number(&segment_name).unwrap_or(0);
            
            // Parse From/To/Size values
            let offset_from = extract_numeric_value(inner, "From:");
            let offset_to = extract_numeric_value(inner, "To:");
            let size = extract_numeric_value(inner, "Size:");
            
            current_segment = Some(SegmentHash {
                segment_name,
                segment_number,
                algorithm: "MD5".to_string(),
                hash: String::new(),
                offset_from,
                offset_to,
                size,
                verified: None,
            });
            continue;
        }
        
        // Look for hash value line: "* ...28A9B613 D6EEFE8A 0515EF0A 675BDEBD..."
        if line.starts_with("* ...") && current_segment.is_some() {
            // Extract hex hash (may be space-separated)
            let hash_part = &line[5..]; // Skip "* ..."
            let hash_part = hash_part.trim_end_matches("...");
            
            // Remove spaces and convert to lowercase
            let hash: String = hash_part
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect::<String>()
                .to_lowercase();
            
            if hash.len() >= 32 {
                if let Some(seg) = current_segment.as_mut() {
                    seg.hash = hash;
                }
            }
        }
    }
    
    // Don't forget the last segment
    if let Some(seg) = current_segment {
        if !seg.hash.is_empty() {
            segments.push(seg);
        }
    }
    
    if segments.is_empty() {
        None
    } else {
        Some(segments)
    }
}

/// Extract segment number from segment name (e.g., "SCHARDT.001" -> 1)
fn extract_segment_number(name: &str) -> Option<u32> {
    // Try to find numeric extension
    if let Some(dot_pos) = name.rfind('.') {
        let ext = &name[dot_pos + 1..];
        if let Ok(num) = ext.parse::<u32>() {
            return Some(num);
        }
    }
    None
}

/// Extract numeric value from a "Key: Value" pattern in a line
fn extract_numeric_value(line: &str, key: &str) -> Option<u64> {
    if let Some(pos) = line.find(key) {
        let after_key = &line[pos + key.len()..];
        // Find the number (may end at comma or end of string)
        let num_str: String = after_key
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if !num_str.is_empty() {
            return num_str.parse().ok();
        }
    }
    None
}
