//! Public API for AD1 container operations

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use tracing::{debug, trace, instrument};

use super::types::{
    Ad1Info, VerifyEntry, AD1_SIGNATURE,
};
use super::parser::Session;
use super::utils::*;
use crate::common::hash::{HashAlgorithm, StreamingHasher};

/// Fast info - only reads headers, doesn't parse full item tree
/// Use this for quick container detection/display
/// This uses lenient validation - will return info even with missing segments
#[instrument]
pub fn info_fast(path: &str) -> Result<Ad1Info, String> {
    debug!("Getting fast AD1 info (headers only)");
    validate_format(path)?;  // Only validate format, not segments
    
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open AD1 file '{path}': {e}"))?;
    
    let segment_header = read_segment_header(&mut file)?;
    let logical_header = read_logical_header(&mut file)?;
    
    // Parse volume info from header
    let volume = parse_volume_info(&mut file);
    
    // Parse companion log file for case metadata
    let companion_log = parse_companion_log(path);
    
    // Get segment files with sizes (includes missing segments)
    let (segment_files, segment_sizes, total_size, missing_segments) = 
        get_segment_files_with_sizes(path, segment_header.segment_number);
    
    let missing = if missing_segments.is_empty() {
        None
    } else {
        Some(missing_segments)
    };
    
    Ok(Ad1Info {
        segment: segment_header_info(&segment_header),
        logical: logical_header_info(&logical_header),
        item_count: 0, // Not parsed in fast mode
        tree: None,
        segment_files: Some(segment_files),
        segment_sizes: Some(segment_sizes),
        total_size: Some(total_size),
        missing_segments: missing,
        volume,
        companion_log,
    })
}

/// Get full AD1 container information
/// Note: This still requires all segments to be present (strict validation via Session::open)
#[instrument]
pub fn info(path: &str, include_tree: bool) -> Result<Ad1Info, String> {
    debug!("Getting AD1 info, include_tree={}", include_tree);
    let session = Session::open(path)?;
    
    let tree = if include_tree {
        let mut entries = Vec::new();
        collect_tree(&session.root_items, "", &mut entries);
        Some(entries)
    } else {
        None
    };
    
    // Get segment files with sizes
    let (segment_files, segment_sizes, total_size, missing_segments) = 
        get_segment_files_with_sizes(path, session.segment_header.segment_number);
    
    let missing = if missing_segments.is_empty() {
        None
    } else {
        Some(missing_segments)
    };
    
    // Parse volume info from the first segment file
    let volume = {
        let mut file = File::open(path)
            .map_err(|e| format!("Failed to open AD1 file for volume info: {e}"))?;
        parse_volume_info(&mut file)
    };
    
    // Parse companion log file for case metadata
    let companion_log = parse_companion_log(path);
    
    Ok(Ad1Info {
        segment: segment_header_info(&session.segment_header),
        logical: logical_header_info(&session.logical_header),
        item_count: session.item_counter,
        tree,
        segment_files: Some(segment_files),
        segment_sizes: Some(segment_sizes),
        total_size: Some(total_size),
        missing_segments: missing,
        volume,
        companion_log,
    })
}

/// Verify file hashes in the container
pub fn verify(path: &str, algorithm: &str) -> Result<Vec<VerifyEntry>, String> {
    verify_with_progress(path, algorithm, |_, _| {})
}

/// Verify with progress callback
pub fn verify_with_progress<F>(path: &str, algorithm: &str, mut progress_callback: F) -> Result<Vec<VerifyEntry>, String>
where
    F: FnMut(usize, usize)
{
    let mut session = Session::open(path)?;
    let algo = HashAlgorithm::from_str(algorithm)?;
    let mut results = Vec::new();
    
    // Count total files for progress
    let total = count_files(&session.root_items);
    let mut current = 0;
    
    // Clone root_items to avoid borrow checker issues
    let root_items = session.root_items.clone();
    
    for item in &root_items {
        session.verify_item_with_progress(item, "", algo, &mut results, &mut current, total, &mut progress_callback)?;
    }
    
    Ok(results)
}

/// Extract container contents to output directory
pub fn extract(path: &str, output_dir: &str) -> Result<(), String> {
    extract_with_progress(path, output_dir, |_, _| {})
}

/// Extract with progress callback
pub fn extract_with_progress<F>(path: &str, output_dir: &str, mut progress_callback: F) -> Result<(), String>
where
    F: FnMut(usize, usize)
{
    let mut session = Session::open(path)?;
    let output_path = Path::new(output_dir);
    
    // Count total files for progress
    let total = count_files(&session.root_items);
    let mut current = 0;
    
    // Clone root_items to avoid borrow checker issues
    let root_items = session.root_items.clone();
    
    for item in &root_items {
        session.extract_item_with_progress(item, output_path, &mut current, total, &mut progress_callback)?;
    }
    
    Ok(())
}

/// Check if file is an AD1 container
pub fn is_ad1(path: &str) -> Result<bool, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open input file: {e}"))?;
    let mut signature = [0u8; 16];
    file.read_exact(&mut signature)
        .map_err(|e| format!("Failed to read file signature: {e}"))?;
    let is_ad1 = &signature[..15] == AD1_SIGNATURE;
    trace!(path, is_ad1, "AD1 signature check");
    Ok(is_ad1)
}

/// Hash AD1 segment files (image-level hash)
/// This hashes all segment files sequentially to produce a single hash
/// that can be compared against the stored hash in the companion log
pub fn hash_segments(path: &str, algorithm: &str) -> Result<String, String> {
    hash_segments_with_progress(path, algorithm, |_, _| {})
}

/// Hash AD1 segments with progress callback
pub fn hash_segments_with_progress<F>(path: &str, algorithm: &str, mut progress_callback: F) -> Result<String, String>
where
    F: FnMut(u64, u64)
{
    validate_input(path)?;
    
    let algo = HashAlgorithm::from_str(algorithm)?;
    
    // Get segment info
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open AD1 file: {e}"))?;
    let segment_header = read_segment_header(&mut file)?;
    drop(file);
    
    let segment_count = segment_header.segment_number;
    
    // Calculate total size for progress
    let mut total_size: u64 = 0;
    let mut segment_paths = Vec::with_capacity(segment_count as usize);
    
    for i in 1..=segment_count {
        let segment_path = build_segment_path(path, i);
        let seg_path = Path::new(&segment_path);
        if !seg_path.exists() {
            return Err(format!("Missing segment: {}", segment_path));
        }
        let size = std::fs::metadata(&segment_path)
            .map(|m| m.len())
            .map_err(|e| format!("Failed to get segment size: {e}"))?;
        total_size += size;
        segment_paths.push(segment_path);
    }
    
    debug!(segment_count, total_size, "Hashing AD1 segments");
    
    // Hash all segments sequentially
    let mut hasher = StreamingHasher::new(algo);
    let mut bytes_processed: u64 = 0;
    let buffer_size = 1024 * 1024; // 1MB buffer
    
    for segment_path in &segment_paths {
        let file = File::open(segment_path)
            .map_err(|e| format!("Failed to open segment {}: {e}", segment_path))?;
        let mut reader = BufReader::with_capacity(buffer_size, file);
        let mut buffer = vec![0u8; buffer_size];
        
        loop {
            let bytes_read = reader.read(&mut buffer)
                .map_err(|e| format!("Failed to read segment: {e}"))?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
            bytes_processed += bytes_read as u64;
            progress_callback(bytes_processed, total_size);
        }
    }
    
    let hash = hasher.finalize();
    debug!(hash = %hash, "AD1 segment hash complete");
    Ok(hash)
}
