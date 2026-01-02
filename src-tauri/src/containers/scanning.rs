//! Directory scanning for forensic containers
//!
//! This module provides functions for discovering forensic container files
//! in directories, with support for streaming results and recursive scanning.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tracing::debug;

use super::types::DiscoveredFile;
use super::segments::{
    is_first_segment, is_numbered_segment, is_archive_segment,
    get_segment_basename, get_first_segment_path_fast,
};

/// Scan a directory for forensic container files (non-recursive)
pub fn scan_directory(dir_path: &str) -> Result<Vec<DiscoveredFile>, String> {
    scan_directory_impl(dir_path, false)
}

/// Scan a directory recursively for forensic container files
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

    let mut seen_basenames = HashSet::new();
    let mut count = 0;

    scan_dir_streaming_internal(path, &mut seen_basenames, recursive, &on_file_found, &mut count)?;

    Ok(count)
}

fn scan_dir_streaming_internal<F>(
    path: &Path,
    seen_basenames: &mut HashSet<String>,
    recursive: bool,
    on_file_found: &F,
    count: &mut usize,
) -> Result<(), String>
where
    F: Fn(&DiscoveredFile),
{
    let entries = fs::read_dir(path)
        .map_err(|e| format!("Failed to read directory: {e}"))?;

    // First pass: collect all entries and find UFD files (to identify UFED extraction sets)
    let mut file_entries = Vec::new();
    let mut ufd_basenames: HashSet<String> = HashSet::new();
    let mut ufd_paths: std::collections::HashMap<String, std::path::PathBuf> = std::collections::HashMap::new();
    let mut subdirs = Vec::new();
    
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Failed to read directory entry: {}", e);
                continue;
            }
        };

        let entry_path = entry.path();
        
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) => {
                tracing::warn!("Failed to get file type for {:?}: {}", entry_path, e);
                continue;
            }
        };
        
        if file_type.is_dir() {
            if recursive {
                subdirs.push(entry_path);
            }
            continue;
        }
        
        if !file_type.is_file() {
            continue;
        }

        let filename = entry.file_name().to_string_lossy().to_string();
        let lower = filename.to_lowercase();
        
        // Track UFD files to identify UFED extraction sets
        if lower.ends_with(".ufd") {
            // Extract basename without extension
            if let Some(stem) = Path::new(&filename).file_stem() {
                let stem_lower = stem.to_string_lossy().to_lowercase();
                ufd_basenames.insert(stem_lower.clone());
                ufd_paths.insert(stem_lower, entry_path.clone());
            }
        }
        
        file_entries.push((entry, filename, lower));
    }
    
    // Recurse into subdirectories
    for subdir in subdirs {
        let _ = scan_dir_streaming_internal(&subdir, seen_basenames, recursive, on_file_found, count);
    }
    
    // Second pass: process files
    // - UFD files are skipped (metadata only, not evidence containers)
    // - UFDX files are skipped (collection index)
    // - ZIP files with matching UFD are detected as "UFED" type containers
    for (entry, filename, lower) in file_entries {
        let entry_path = entry.path();
        
        let path_str = match entry_path.to_str() {
            Some(s) => s,
            None => continue,
        };

        // Skip macOS resource fork files (._filename)
        if filename.starts_with("._") {
            continue;
        }
        
        // Skip non-first segments entirely - we only want to show one entry per container
        if !is_first_segment(&lower) {
            continue;
        }
        
        // Skip UFDX files - these are collection indexes/pointers, not evidence containers
        // They point to actual evidence but contain no evidence data themselves
        if lower.ends_with(".ufdx") {
            debug!("Skipping UFED collection index: {} (metadata pointer, not evidence)", filename);
            continue;
        }
        
        // Skip UFD files when they exist alongside matching ZIP (metadata only)
        if !ufd_basenames.is_empty() && lower.ends_with(".ufd") {
            debug!("Skipping UFED metadata file: {} (metadata only)", filename);
            continue;
        }
        
        // Check for forensic container files by extension only (fast, no file I/O)
        // Special case: ZIP files with sibling UFD are UFED extraction containers
        let container_type = if lower.ends_with(".zip") {
            if let Some(stem) = Path::new(&filename).file_stem() {
                let stem_lower = stem.to_string_lossy().to_lowercase();
                if ufd_paths.contains_key(&stem_lower) {
                    Some("UFED")
                } else {
                    detect_container_type_by_extension(&lower)
                }
            } else {
                detect_container_type_by_extension(&lower)
            }
        } else {
            detect_container_type_by_extension(&lower)
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
                
                // Extract timestamps from metadata
                let created = metadata.as_ref()
                    .and_then(|m| m.created().ok())
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Local> = t.into();
                        dt.format("%Y-%m-%d %H:%M:%S").to_string()
                    });
                let modified = metadata.as_ref()
                    .and_then(|m| m.modified().ok())
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Local> = t.into();
                        dt.format("%Y-%m-%d %H:%M:%S").to_string()
                    });
                
                // FAST PATH: Skip segment calculation during scan - it's slow on external drives
                // Segment details will be calculated on-demand when user selects a file
                
                let file = DiscoveredFile {
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
                };
                
                on_file_found(&file);
                *count += 1;
            } else {
                debug!("Skipping duplicate basename: {}", filename);
            }
        } else {
            debug!("Skipping file with unrecognized container type: {}", filename);
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
    let mut seen_basenames = HashSet::new();

    scan_dir_internal(path, &mut discovered, &mut seen_basenames, recursive)?;

    Ok(discovered)
}

fn scan_dir_internal(
    path: &Path,
    discovered: &mut Vec<DiscoveredFile>,
    seen_basenames: &mut HashSet<String>,
    recursive: bool,
) -> Result<(), String> {
    let entries = fs::read_dir(path)
        .map_err(|e| format!("Failed to read directory: {e}"))?;

    // First pass: collect all entries and find UFD files (to identify UFED extraction sets)
    let mut file_entries = Vec::new();
    let mut ufd_basenames: HashSet<String> = HashSet::new();
    let mut subdirs = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Failed to read directory entry: {}", e);
                continue;
            }
        };

        let entry_path = entry.path();
        
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) => {
                tracing::warn!("Failed to get file type for {:?}: {}", entry_path, e);
                continue;
            }
        };
        
        if file_type.is_dir() {
            if recursive {
                subdirs.push(entry_path);
            }
            continue;
        }
        
        if !file_type.is_file() {
            continue;
        }

        let filename = entry.file_name().to_string_lossy().to_string();
        let lower = filename.to_lowercase();
        
        // Track UFD files to identify UFED extraction sets
        if lower.ends_with(".ufd") {
            if let Some(stem) = Path::new(&filename).file_stem() {
                let stem_lower = stem.to_string_lossy().to_lowercase();
                ufd_basenames.insert(stem_lower);
            }
        }
        
        file_entries.push((entry, filename, lower));
    }
    
    // Recurse into subdirectories
    for subdir in subdirs {
        let _ = scan_dir_internal(&subdir, discovered, seen_basenames, recursive);
    }

    // Second pass: process files
    // - UFD files are skipped (metadata only, not evidence containers)
    // - UFDX files are skipped (collection index)
    // - ZIP files with matching UFD are detected as "UFED" type containers
    for (entry, filename, lower) in file_entries {
        let entry_path = entry.path();
        
        let path_str = match entry_path.to_str() {
            Some(s) => s,
            None => {
                tracing::warn!("Failed to convert path to string: {:?}", entry_path);
                continue;
            }
        };

        // Skip macOS resource fork files (._filename)
        if filename.starts_with("._") {
            continue;
        }
        
        // Skip non-first segments entirely - we only want to show one entry per container
        if !is_first_segment(&lower) {
            continue;
        }
        
        // Skip UFDX files - these are collection indexes/pointers, not evidence containers
        // They point to actual evidence but contain no evidence data themselves
        if lower.ends_with(".ufdx") {
            debug!("Skipping UFED collection index: {} (metadata pointer, not evidence)", filename);
            continue;
        }
        
        // Skip UFD files when they exist alongside matching ZIP (metadata only)
        if !ufd_basenames.is_empty() && lower.ends_with(".ufd") {
            debug!("Skipping UFED metadata file: {} (metadata only)", filename);
            continue;
        }
        
        // Check for forensic container files by extension only (fast, no file I/O)
        // Special case: ZIP files with sibling UFD are UFED extraction containers
        let container_type = if lower.ends_with(".zip") {
            if let Some(stem) = Path::new(&filename).file_stem() {
                let stem_lower = stem.to_string_lossy().to_lowercase();
                if ufd_basenames.contains(&stem_lower) {
                    Some("UFED")
                } else {
                    detect_container_type_by_extension(&lower)
                }
            } else {
                detect_container_type_by_extension(&lower)
            }
        } else {
            detect_container_type_by_extension(&lower)
        };

        if let Some(ctype) = container_type {
            // For multi-segment files (like .E01, .001), only show the first segment
            let basename = get_segment_basename(&filename);
            if seen_basenames.insert(basename.clone()) {
                // For numbered segments, always use the first segment path (.001)
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
                
                // Extract timestamps from metadata
                let created = metadata.as_ref()
                    .and_then(|m| m.created().ok())
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Local> = t.into();
                        dt.format("%Y-%m-%d %H:%M:%S").to_string()
                    });
                let modified = metadata.as_ref()
                    .and_then(|m| m.modified().ok())
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Local> = t.into();
                        dt.format("%Y-%m-%d %H:%M:%S").to_string()
                    });
                
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
            } else {
                debug!("Skipping duplicate basename: {}", filename);
            }
        } else {
            debug!("Skipping file with unrecognized container type: {}", filename);
        }
    }

    Ok(())
}

/// Detect container type by file extension only (fast, no file I/O)
/// Returns None for unrecognized extensions
fn detect_container_type_by_extension(lower: &str) -> Option<&'static str> {
    // =========================================================================
    // Forensic Containers (evidence preservation formats)
    // =========================================================================
    if lower.ends_with(".ad1") {
        Some("AD1")
    } else if lower.ends_with(".l01") {
        Some("L01")
    } else if lower.ends_with(".lx01") {
        Some("Lx01")
    } else if lower.ends_with(".e01") {
        Some("EnCase (E01)")
    } else if lower.ends_with(".ex01") {
        Some("EnCase (Ex01)")
    } else if lower.ends_with(".aff") || lower.ends_with(".afd") {
        Some("AFF")
    } else if lower.ends_with(".aff4") {
        Some("AFF4")
    } else if lower.ends_with(".s01") || lower.ends_with(".s02") {
        Some("SMART")
    // =========================================================================
    // UFED Mobile Forensics
    // =========================================================================
    } else if lower.ends_with(".ufdr") {
        Some("UFED (UFDR)")
    } else if lower.ends_with(".ufdx") {
        // UFDX files are collection indexes/pointers, not evidence containers
        // They point to actual evidence but contain no evidence data themselves
        None
    } else if lower.ends_with(".ufd") {
        Some("UFED (UFD)")
    // =========================================================================
    // Compression Archives
    // =========================================================================
    } else if lower.ends_with(".7z") || lower.ends_with(".7z.001") {
        Some("7-Zip")
    } else if lower.ends_with(".zip") || lower.ends_with(".zip.001") || lower.ends_with(".z01") {
        Some("ZIP")
    } else if lower.ends_with(".rar") || lower.ends_with(".r00") {
        Some("RAR")
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        Some("TAR.GZ")
    } else if lower.ends_with(".tar.xz") || lower.ends_with(".txz") {
        Some("TAR.XZ")
    } else if lower.ends_with(".tar.bz2") || lower.ends_with(".tbz2") {
        Some("TAR.BZ2")
    } else if lower.ends_with(".tar.zst") {
        Some("TAR.ZSTD")
    } else if lower.ends_with(".tar.lz4") {
        Some("TAR.LZ4")
    } else if lower.ends_with(".tar") {
        if lower.contains("logical") {
            Some("TAR (Logical)")
        } else {
            Some("TAR")
        }
    } else if lower.ends_with(".gz") && !lower.ends_with(".tar.gz") {
        Some("GZIP")
    } else if lower.ends_with(".xz") && !lower.ends_with(".tar.xz") {
        Some("XZ")
    } else if lower.ends_with(".bz2") && !lower.ends_with(".tar.bz2") {
        Some("BZIP2")
    } else if lower.ends_with(".zst") || lower.ends_with(".zstd") {
        Some("ZSTD")
    } else if lower.ends_with(".lz4") && !lower.ends_with(".tar.lz4") {
        Some("LZ4")
    // =========================================================================
    // Virtual Machine Disk Images
    // =========================================================================
    } else if lower.ends_with(".vmdk") {
        Some("VMDK")
    } else if lower.ends_with(".vhd") {
        Some("VHD")
    } else if lower.ends_with(".vhdx") {
        Some("VHDX")
    } else if lower.ends_with(".qcow2") || lower.ends_with(".qcow") {
        Some("QCOW2")
    } else if lower.ends_with(".vdi") {
        Some("VDI")
    // =========================================================================
    // macOS Disk Images
    // =========================================================================
    } else if lower.ends_with(".dmg") {
        Some("DMG")
    } else if lower.ends_with(".sparsebundle") || lower.ends_with(".sparseimage") {
        Some("Apple Sparse Image")
    // =========================================================================
    // Optical Disc Images
    // =========================================================================
    } else if lower.ends_with(".iso") {
        Some("ISO 9660")
    } else if lower.ends_with(".bin") || lower.ends_with(".cue") {
        Some("BIN/CUE")
    // =========================================================================
    // Raw Disk Images
    // =========================================================================
    } else if is_numbered_segment(lower) && !is_archive_segment(lower) {
        // Raw image segments (.001, .002, etc.) - but not archive segments
        Some("Raw Image")
    } else if lower.ends_with(".dd") || lower.ends_with(".raw") || lower.ends_with(".img") {
        Some("Raw Image")
    } else {
        None
    }
}
