use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::ad1;
use crate::ewf;  // Expert Witness Format (E01/EWF/Ex01)
use crate::l01;
use crate::raw;  // Raw disk images (.dd, .raw, .img, .001)

#[derive(Serialize)]
pub struct ContainerInfo {
    pub container: String,
    pub ad1: Option<ad1::Ad1Info>,
    pub e01: Option<ewf::E01Info>,
    pub l01: Option<l01::L01Info>,
    pub raw: Option<raw::RawInfo>,
    pub note: Option<String>,
}

#[derive(Serialize)]
pub struct DiscoveredFile {
    pub path: String,
    pub filename: String,
    pub container_type: String,
    pub size: u64,
    pub segment_count: Option<u32>,
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
}

pub fn info(path: &str, include_tree: bool) -> Result<ContainerInfo, String> {
    let kind = detect_container(path)?;
    match kind {
        ContainerKind::Ad1 => {
            let info = ad1::info(path, include_tree)?;
            Ok(ContainerInfo {
                container: "AD1".to_string(),
                ad1: Some(info),
                e01: None,
                l01: None,
                raw: None,
                note: None,
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
                note: None,
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
                note: None,
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
                note: None,
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
    }
}

pub fn extract(path: &str, output_dir: &str) -> Result<(), String> {
    match detect_container(path)? {
        ContainerKind::Ad1 => ad1::extract(path, output_dir),
        ContainerKind::E01 => ewf::extract(path, output_dir),
        ContainerKind::L01 => Err("L01 extraction is not implemented yet.".to_string()),
        ContainerKind::Raw => raw::extract(path, output_dir),
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
    if (lower.ends_with(".e01") || lower.ends_with(".ex01") || lower.ends_with(".ewf") 
        || lower.contains(".e0") || lower.contains(".ex"))
        && ewf::is_e01(path).unwrap_or(false) 
    {
        return Ok(ContainerKind::E01);
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

    // Check raw disk images (.dd, .raw, .img, .001, .002, etc.)
    if raw::is_raw(path).unwrap_or(false) {
        return Ok(ContainerKind::Raw);
    }

    Err(format!("Unsupported or unrecognized logical container: {}\nSupported formats: AD1, E01/EWF, L01, RAW (.dd, .raw, .img, .001)", path))
}

pub fn scan_directory(dir_path: &str) -> Result<Vec<DiscoveredFile>, String> {
    scan_directory_impl(dir_path, false)
}

pub fn scan_directory_recursive(dir_path: &str) -> Result<Vec<DiscoveredFile>, String> {
    scan_directory_impl(dir_path, true)
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
        
        // Recurse into subdirectories if enabled
        if recursive && entry_path.is_dir() {
            let _ = scan_dir_internal(&entry_path, discovered, seen_basenames, recursive);
            continue;
        }
        
        if !entry_path.is_file() {
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

        let lower = filename.to_lowercase();
        
        // Check for forensic container files
        let container_type = if lower.ends_with(".ad1") || lower.ends_with(".ad2") || lower.ends_with(".ad3") {
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
        } else if is_encase_image(&lower) {
            Some("EnCase (E01)")
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
                let size = entry.metadata()
                    .map(|m| m.len())
                    .unwrap_or(0);

                // For segmented files, try to calculate total size and count
                let parent_dir = entry_path.parent().unwrap_or(path);
                let (total_size, segment_count) = if is_segmented_file(&lower) {
                    let (size, count) = calculate_total_segment_info(parent_dir, &basename).unwrap_or((size, None));
                    (size, count)
                } else {
                    (size, None)
                };

                discovered.push(DiscoveredFile {
                    path: path_str.to_string(),
                    filename,
                    container_type: ctype.to_string(),
                    size: total_size,
                    segment_count,
                });
            }
        }
    }

    Ok(())
}

/// Check if filename matches EnCase image pattern (E01 or numbered segments like .001)
fn is_encase_image(lower: &str) -> bool {
    if lower.ends_with(".e01") {
        return true;
    }
    // Check for .001, .002, etc. pattern (SCHARDT.001, PC-MUS-001.E01)
    if let Some(ext_start) = lower.rfind('.') {
        let ext = &lower[ext_start + 1..];
        if ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    false
}

/// Check if file is part of a segmented series
fn is_segmented_file(lower: &str) -> bool {
    is_encase_image(lower) || lower.ends_with(".e02") || lower.ends_with(".ex01")
}

/// Get the base name without segment number for grouping
fn get_segment_basename(filename: &str) -> String {
    let lower = filename.to_lowercase();
    
    // Handle .E01, .E02, etc.
    if lower.ends_with(".e01") {
        return filename[..filename.len() - 4].to_string();
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

/// Calculate total size of all segments in a series
fn calculate_total_segment_info(dir: &Path, basename: &str) -> Option<(u64, Option<u32>)> {
    let mut total = 0u64;
    let mut count = 0u32;
    
    // Try common segment patterns
    let patterns = [
        format!("{}.E01", basename),
        format!("{}.001", basename),
    ];
    
    for pattern in &patterns {
        let mut segment_num = 1;
        // Limit to 100 segments max to prevent infinite loops
        while segment_num <= 100 {
            let segment_name = if pattern.contains(".E01") {
                if segment_num == 1 {
                    format!("{}.E01", basename)
                } else {
                    format!("{}.E{:02}", basename, segment_num)
                }
            } else {
                format!("{}.{:03}", basename, segment_num)
            };
            
            let segment_path = dir.join(&segment_name);
            if let Ok(metadata) = segment_path.metadata() {
                total += metadata.len();
                count += 1;
                segment_num += 1;
            } else {
                // Stop at first missing segment
                break;
            }
        }
        
        if total > 0 {
            return Some((total, if count > 1 { Some(count) } else { None }));
        }
    }
    
    None
}
