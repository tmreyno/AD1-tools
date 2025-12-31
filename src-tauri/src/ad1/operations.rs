//! Public API for AD1 container operations

use std::fs::File;
use std::io::Read;
use std::path::Path;
use tracing::{debug, trace, instrument};

use super::types::{
    Ad1Info, VerifyEntry, AD1_SIGNATURE,
};
use super::parser::Session;
use super::utils::*;
use crate::common::hash::HashAlgorithm;

/// Fast info - only reads headers, doesn't parse full item tree
/// Use this for quick container detection/display
#[instrument]
pub fn info_fast(path: &str) -> Result<Ad1Info, String> {
    debug!("Getting fast AD1 info (headers only)");
    validate_input(path)?;
    
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open AD1 file '{path}': {e}"))?;
    
    let segment_header = read_segment_header(&mut file)?;
    let logical_header = read_logical_header(&mut file)?;
    
    // Parse volume info from header
    let volume = parse_volume_info(&mut file);
    
    // Parse companion log file for case metadata
    let companion_log = parse_companion_log(path);
    
    // Get segment file list
    let segment_files = get_segment_files(path, segment_header.segment_number);
    
    Ok(Ad1Info {
        segment: segment_header_info(&segment_header),
        logical: logical_header_info(&logical_header),
        item_count: 0, // Not parsed in fast mode
        tree: None,
        segment_files: Some(segment_files),
        volume,
        companion_log,
    })
}

/// Get full AD1 container information
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
    
    let segment_files = get_segment_files(path, session.segment_header.segment_number);
    
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
