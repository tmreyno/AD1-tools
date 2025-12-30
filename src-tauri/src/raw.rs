//! RAW Disk Image Parser
//!
//! This module provides parsing and verification for raw (dd-style) forensic
//! disk images, supporting both single-file and multi-segment formats.
//!
//! ## Supported Formats
//!
//! | Extension     | Description                           |
//! |---------------|---------------------------------------|
//! | `.dd`         | Standard dd-style raw image           |
//! | `.raw`        | Generic raw disk image                |
//! | `.img`        | Disk image (verify magic to disambiguate) |
//! | `.001`-`.999` | Multi-segment numbered format         |
//!
//! ## Multi-Segment Images
//!
//! Raw images can be split into numbered segments:
//!
//! ```text
//! evidence.001  ─┐
//! evidence.002   │  Combined: Single contiguous byte stream
//! evidence.003   │  representing the original disk image
//! evidence.004  ─┘
//! ```
//!
//! Segment discovery:
//! 1. Detect if input file has numeric extension (.001, .002, etc.)
//! 2. Scan directory for matching basename with sequential numbers
//! 3. Sort segments by number, verify no gaps
//! 4. Concatenate virtually for seamless reading
//!
//! ## RawHandle
//!
//! The `RawHandle` provides a virtual file-like interface over segmented images:
//!
//! ```rust,ignore
//! let mut handle = RawHandle::open("/evidence/disk.001")?;
//!
//! // Read seamlessly across segment boundaries
//! let mut buf = vec![0u8; 1024];
//! let bytes_read = handle.read(&mut buf)?;
//!
//! // Total size spans all segments
//! let total_size = handle.total_size();
//! ```
//!
//! ## Hash Verification
//!
//! High-performance hashing with algorithm-specific optimizations:
//!
//! | Algorithm | Implementation                              |
//! |-----------|---------------------------------------------|
//! | BLAKE3    | Memory-mapped I/O + rayon parallel hashing  |
//! | XXH3      | Memory-mapped I/O, extremely fast           |
//! | SHA-256   | Pipelined: async I/O → hasher thread        |
//! | MD5       | Pipelined I/O (legacy, not recommended)     |
//!
//! ```rust,ignore
//! // Verify with progress callback
//! raw::verify_with_progress("/evidence/disk.001", "sha256", |current, total| {
//!     let percent = (current as f64 / total as f64) * 100.0;
//!     println!("Progress: {:.1}%", percent);
//! })?;
//! ```
//!
//! ## Forensic Notes
//!
//! - Raw images preserve **physical** disk layout (sector-by-sector)
//! - No compression or metadata - pure byte-for-byte copy
//! - Hash of raw image = hash of original disk
//! - Segment boundaries have NO forensic significance
//!   (they're just split points, not disk boundaries)
//! - For evidentiary purposes, always hash the **complete** image
//!
//! ## Performance
//!
//! Buffer sizes and threading are tuned for modern storage:
//! - 16MB I/O buffers for sequential throughput
//! - Memory-mapped I/O for >64MB files
//! - Parallel hashing for BLAKE3
//! - Pipelined I/O for other algorithms

// RAW disk image parser (.dd, .raw, .img, .001, .002, etc.)
// Supports single and multi-segment raw forensic images

use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, BufReader};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use tracing::{debug, trace, info, instrument};

use crate::common::{BUFFER_SIZE, hash::StreamingHasher, segments::discover_numbered_segments};

// =============================================================================
// Public Types
// =============================================================================

#[derive(Serialize, Clone)]
pub struct RawInfo {
    pub segment_count: u32,
    pub total_size: u64,
    pub segment_sizes: Vec<u64>,
    pub segment_names: Vec<String>,
    pub first_segment: String,
    pub last_segment: String,
}

#[derive(Serialize)]
pub struct VerifyResult {
    pub algorithm: String,
    pub hash: String,
    pub total_size: u64,
    pub duration_secs: f64,
    pub throughput_mbs: f64,
}

// =============================================================================
// Raw Image Handle
// =============================================================================

pub struct RawHandle {
    segments: Vec<PathBuf>,
    segment_sizes: Vec<u64>,
    total_size: u64,
    current_segment: usize,
    current_file: Option<File>,
    position: u64,
}

impl RawHandle {
    /// Open a raw image (single or multi-segment)
    pub fn open(path: &str) -> Result<Self, String> {
        let path_obj = Path::new(path);
        if !path_obj.exists() {
            return Err(format!("File not found: {}", path));
        }

        let (segments, segment_sizes) = discover_segments(path)?;
        let total_size: u64 = segment_sizes.iter().sum();

        Ok(RawHandle {
            segments,
            segment_sizes,
            total_size,
            current_segment: 0,
            current_file: None,
            position: 0,
        })
    }

    /// Get total size of all segments
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Get segment count
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Read bytes at current position
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        if self.position >= self.total_size {
            return Ok(0);
        }

        let mut total_read = 0;
        let mut remaining = buf.len();

        while remaining > 0 && self.position < self.total_size {
            // Find which segment we're in
            let (seg_idx, seg_offset) = self.position_to_segment(self.position);
            
            // Open segment if needed
            if self.current_segment != seg_idx || self.current_file.is_none() {
                self.current_segment = seg_idx;
                let file = File::open(&self.segments[seg_idx])
                    .map_err(|e| format!("Failed to open segment {}: {}", seg_idx, e))?;
                self.current_file = Some(file);
            }

            let file = self.current_file.as_mut().unwrap();
            file.seek(SeekFrom::Start(seg_offset))
                .map_err(|e| format!("Seek failed: {}", e))?;

            // Calculate how much we can read from this segment
            let seg_remaining = self.segment_sizes[seg_idx] - seg_offset;
            let to_read = remaining.min(seg_remaining as usize);

            let bytes_read = file.read(&mut buf[total_read..total_read + to_read])
                .map_err(|e| format!("Read failed: {}", e))?;

            if bytes_read == 0 {
                break;
            }

            total_read += bytes_read;
            remaining -= bytes_read;
            self.position += bytes_read as u64;
        }

        Ok(total_read)
    }

    /// Convert absolute position to (segment_index, offset_within_segment)
    fn position_to_segment(&self, pos: u64) -> (usize, u64) {
        let mut offset = pos;
        for (idx, &size) in self.segment_sizes.iter().enumerate() {
            if offset < size {
                return (idx, offset);
            }
            offset -= size;
        }
        // Past end - return last segment
        let last = self.segments.len() - 1;
        (last, self.segment_sizes[last])
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Get information about a raw image
#[instrument]
pub fn info(path: &str) -> Result<RawInfo, String> {
    debug!("Getting raw image info");
    let handle = RawHandle::open(path)?;
    
    // Extract just filenames for display
    let segment_names: Vec<String> = handle.segments.iter()
        .map(|p| p.file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default())
        .collect();
    
    debug!(
        segment_count = handle.segment_count(),
        total_size = handle.total_size(),
        "Raw image info loaded"
    );
    
    Ok(RawInfo {
        segment_count: handle.segment_count() as u32,
        total_size: handle.total_size(),
        segment_sizes: handle.segment_sizes.clone(),
        segment_names,
        first_segment: handle.segments.first()
            .map(|p| p.file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default())
            .unwrap_or_default(),
        last_segment: handle.segments.last()
            .map(|p| p.file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default())
            .unwrap_or_default(),
    })
}

/// Check if a file is a raw image (by extension)
pub fn is_raw(path: &str) -> Result<bool, String> {
    let lower = path.to_lowercase();
    
    // Check common raw extensions
    if lower.ends_with(".dd") || lower.ends_with(".raw") || lower.ends_with(".img") {
        trace!(path, "Detected as raw by extension");
        return Ok(true);
    }
    
    // Check numeric extensions (.001, .002, etc.)
    if let Some(ext_start) = lower.rfind('.') {
        let ext = &lower[ext_start + 1..];
        if ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()) {
            return Ok(true);
        }
    }
    
    Ok(false)
}

/// Verify raw image with specified hash algorithm
pub fn verify(path: &str, algorithm: &str) -> Result<String, String> {
    verify_with_progress(path, algorithm, |_, _| {})
}

/// Verify with progress callback - OPTIMIZED with pipelined I/O and hashing
#[instrument(skip(progress_callback))]
pub fn verify_with_progress<F>(path: &str, algorithm: &str, progress_callback: F) -> Result<String, String>
where
    F: FnMut(u64, u64)
{
    debug!("Starting raw image verification");
    let handle = RawHandle::open(path)?;
    let total_size = handle.total_size();
    let algorithm_lower = algorithm.to_lowercase();

    // Validate algorithm
    let valid_algo = matches!(algorithm_lower.as_str(), 
        "md5" | "sha1" | "sha-1" | "sha256" | "sha-256" | 
        "sha512" | "sha-512" | "blake3" | "blake2" | "blake2b" |
        "xxh3" | "xxh64" | "crc32");
    
    if !valid_algo {
        return Err(format!("Unsupported algorithm: {}. Supported: md5, sha1, sha256, sha512, blake3, blake2, xxh3, xxh64, crc32", algorithm));
    }

    debug!(algorithm = algorithm_lower.as_str(), total_size, "Verifying with algorithm");

    // For BLAKE3, use its built-in parallel hashing with memory-mapped I/O
    if algorithm_lower == "blake3" {
        return verify_blake3_optimized(path, total_size, progress_callback);
    }
    
    // For XXH3, use memory-mapped I/O for maximum speed
    if algorithm_lower == "xxh3" {
        return verify_xxh3_optimized(path, total_size, progress_callback);
    }

    // For other algorithms, use pipelined I/O -> hashing
    verify_pipelined(path, &algorithm_lower, total_size, progress_callback)
}

/// BLAKE3 optimized path - uses memory-mapped I/O + rayon parallel hashing
fn verify_blake3_optimized<F>(path: &str, total_size: u64, mut progress_callback: F) -> Result<String, String>
where
    F: FnMut(u64, u64)
{
    use memmap2::Mmap;
    use crate::common::MMAP_THRESHOLD;
    
    let mut hasher = blake3::Hasher::new();
    let segments = discover_segments(path)?.0;
    let mut bytes_processed = 0u64;
    let report_interval = (total_size / 50).max(BUFFER_SIZE as u64); // Report ~50 times
    let mut last_report = 0u64;
    
    for seg_path in &segments {
        let file = File::open(seg_path)
            .map_err(|e| format!("Failed to open segment: {}", e))?;
        let seg_size = file.metadata()
            .map_err(|e| format!("Failed to get segment size: {}", e))?
            .len();
        
        // Use memory-mapped I/O for large segments (faster than buffered read)
        if seg_size >= MMAP_THRESHOLD {
            // SAFETY: File is opened read-only, mmap is safe for read access
            let mmap = unsafe { Mmap::map(&file) }
                .map_err(|e| format!("Failed to memory-map segment: {}", e))?;
            
            // Process in chunks for progress reporting
            let chunk_size = BUFFER_SIZE;
            for chunk in mmap.chunks(chunk_size) {
                hasher.update_rayon(chunk);
                bytes_processed += chunk.len() as u64;
                
                if bytes_processed - last_report >= report_interval {
                    progress_callback(bytes_processed, total_size);
                    last_report = bytes_processed;
                }
            }
        } else {
            // Small files: use buffered read
            use std::io::BufRead;
            let mut reader = std::io::BufReader::with_capacity(BUFFER_SIZE, file);
            
            loop {
                let buf = reader.fill_buf()
                    .map_err(|e| format!("Read error: {}", e))?;
                let len = buf.len();
                if len == 0 { break; }
                
                hasher.update_rayon(buf);
                reader.consume(len);
                
                bytes_processed += len as u64;
                if bytes_processed - last_report >= report_interval {
                    progress_callback(bytes_processed, total_size);
                    last_report = bytes_processed;
                }
            }
        }
    }
    
    progress_callback(total_size, total_size);
    Ok(hasher.finalize().to_hex().to_string())
}

/// XXH3 optimized path - uses memory-mapped I/O for maximum speed
/// XXH3 is ~10x faster than SHA-256 for non-cryptographic checksums
fn verify_xxh3_optimized<F>(path: &str, total_size: u64, mut progress_callback: F) -> Result<String, String>
where
    F: FnMut(u64, u64)
{
    use memmap2::Mmap;
    use xxhash_rust::xxh3::Xxh3;
    use crate::common::MMAP_THRESHOLD;
    
    let mut hasher = Xxh3::new();
    let segments = discover_segments(path)?.0;
    let mut bytes_processed = 0u64;
    let report_interval = (total_size / 50).max(BUFFER_SIZE as u64);
    let mut last_report = 0u64;
    
    for seg_path in &segments {
        let file = File::open(seg_path)
            .map_err(|e| format!("Failed to open segment: {}", e))?;
        let seg_size = file.metadata()
            .map_err(|e| format!("Failed to get segment size: {}", e))?
            .len();
        
        // Use memory-mapped I/O for large segments
        if seg_size >= MMAP_THRESHOLD {
            let mmap = unsafe { Mmap::map(&file) }
                .map_err(|e| format!("Failed to memory-map segment: {}", e))?;
            
            // Process in chunks for progress reporting
            let chunk_size = BUFFER_SIZE;
            for chunk in mmap.chunks(chunk_size) {
                hasher.update(chunk);
                bytes_processed += chunk.len() as u64;
                
                if bytes_processed - last_report >= report_interval {
                    progress_callback(bytes_processed, total_size);
                    last_report = bytes_processed;
                }
            }
        } else {
            // Small files: use buffered read
            use std::io::BufRead;
            let mut reader = std::io::BufReader::with_capacity(BUFFER_SIZE, file);
            
            loop {
                let buf = reader.fill_buf()
                    .map_err(|e| format!("Read error: {}", e))?;
                let len = buf.len();
                if len == 0 { break; }
                
                hasher.update(buf);
                reader.consume(len);
                
                bytes_processed += len as u64;
                if bytes_processed - last_report >= report_interval {
                    progress_callback(bytes_processed, total_size);
                    last_report = bytes_processed;
                }
            }
        }
    }
    
    progress_callback(total_size, total_size);
    Ok(format!("{:016x}", hasher.digest128()))
}

/// Pipelined verification: I/O thread feeds data to hashing thread
fn verify_pipelined<F>(path: &str, algorithm: &str, total_size: u64, mut progress_callback: F) -> Result<String, String>
where
    F: FnMut(u64, u64)
{
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    
    let segments = discover_segments(path)?.0;
    let algo = algorithm.to_string();
    
    // Shared progress counter
    let bytes_hashed = Arc::new(AtomicU64::new(0));
    let bytes_hashed_clone = Arc::clone(&bytes_hashed);
    
    // Channel with 4 buffer slots for pipelining (allows I/O to stay ahead)
    let (tx, rx) = mpsc::sync_channel::<Option<Vec<u8>>>(4);
    
    // I/O thread: reads segments and sends buffers
    let io_handle = thread::spawn(move || -> Result<(), String> {
        for seg_path in &segments {
            let file = File::open(seg_path)
                .map_err(|e| format!("Failed to open segment {:?}: {}", seg_path, e))?;
            let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
            
            loop {
                let mut buf = vec![0u8; BUFFER_SIZE];
                let bytes_read = reader.read(&mut buf)
                    .map_err(|e| format!("Read error: {}", e))?;
                
                if bytes_read == 0 { break; }
                
                buf.truncate(bytes_read);
                if tx.send(Some(buf)).is_err() {
                    return Err("Hash thread terminated early".to_string());
                }
            }
        }
        // Signal completion
        let _ = tx.send(None);
        Ok(())
    });
    
    // Hashing thread: receives buffers and updates hash using StreamingHasher
    let hash_handle = thread::spawn(move || -> Result<String, String> {
        let mut hasher = StreamingHasher::from_str(&algo)?;
        
        // Process incoming buffers
        while let Ok(Some(buf)) = rx.recv() {
            let len = buf.len() as u64;
            hasher.update(&buf);
            bytes_hashed_clone.fetch_add(len, Ordering::Relaxed);
        }
        
        // Finalize and return hash
        Ok(hasher.finalize())
    });
    
    // Progress reporting in main thread
    let report_interval = (total_size / 100).max(1);
    let mut last_reported = 0u64;
    
    loop {
        let current = bytes_hashed.load(Ordering::Relaxed);
        if current >= total_size { break; }
        
        if current - last_reported >= report_interval {
            progress_callback(current, total_size);
            last_reported = current;
        }
        
        // Check if I/O thread finished
        if io_handle.is_finished() {
            break;
        }
        
        thread::sleep(std::time::Duration::from_millis(50));
    }
    
    // Wait for threads
    io_handle.join()
        .map_err(|_| "I/O thread panicked")?
        .map_err(|e| format!("I/O error: {}", e))?;
    
    let hash = hash_handle.join()
        .map_err(|_| "Hash thread panicked")?
        .map_err(|e| format!("Hash error: {}", e))?;
    
    progress_callback(total_size, total_size);
    Ok(hash)
}

/// Result of verifying a single segment
#[derive(Serialize, Clone)]
pub struct SegmentVerifyResult {
    pub segment_name: String,
    pub segment_number: u32,
    pub algorithm: String,
    pub computed_hash: String,
    pub expected_hash: Option<String>,
    pub verified: Option<bool>,  // None = no expected hash, Some(true) = match, Some(false) = mismatch
    pub size: u64,
    pub duration_secs: f64,
}

/// Verify a single segment file and return hash - OPTIMIZED with buffered I/O
#[instrument(skip(progress_callback))]
pub fn hash_single_segment<F>(segment_path: &str, algorithm: &str, mut progress_callback: F) -> Result<String, String>
where
    F: FnMut(u64, u64)
{
    use std::io::BufRead;
    
    let path = Path::new(segment_path);
    if !path.exists() {
        return Err(format!("Segment file not found: {}", segment_path));
    }
    
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;
    let total_size = metadata.len();
    
    debug!(segment_path, algorithm, total_size, "Hashing single segment");
    
    let file = File::open(path)
        .map_err(|e| format!("Failed to open segment: {}", e))?;
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
    
    let algorithm_lower = algorithm.to_lowercase();
    
    // For BLAKE3, use parallel hashing for best performance
    if algorithm_lower == "blake3" {
        trace!("Using BLAKE3 parallel hashing");
        let mut hasher = blake3::Hasher::new();
        let mut bytes_read_total = 0u64;
        let report_interval = (total_size / 20).max(BUFFER_SIZE as u64);
        let mut last_report = 0u64;
        
        loop {
            let buf = reader.fill_buf()
                .map_err(|e| format!("Read error: {}", e))?;
            let len = buf.len();
            if len == 0 { break; }
            
            hasher.update_rayon(buf);
            reader.consume(len);
            
            bytes_read_total += len as u64;
            if bytes_read_total - last_report >= report_interval {
                progress_callback(bytes_read_total, total_size);
                last_report = bytes_read_total;
            }
        }
        
        progress_callback(total_size, total_size);
        let hash = hasher.finalize().to_hex().to_string();
        info!(segment_path, hash = hash.as_str(), "Segment hash complete");
        return Ok(hash);
    }
    
    // For other algorithms, use StreamingHasher
    let mut hasher = StreamingHasher::from_str(algorithm)?;
    
    let mut bytes_read_total = 0u64;
    let report_interval = (total_size / 20).max(BUFFER_SIZE as u64);
    let mut last_report = 0u64;
    
    loop {
        let buf = reader.fill_buf()
            .map_err(|e| format!("Read error: {}", e))?;
        let len = buf.len();
        if len == 0 { break; }
        
        hasher.update(buf);
        reader.consume(len);
        bytes_read_total += len as u64;
        
        if bytes_read_total - last_report >= report_interval {
            progress_callback(bytes_read_total, total_size);
            last_report = bytes_read_total;
        }
    }
    
    progress_callback(total_size, total_size);
    Ok(hasher.finalize())
}

/// Get all segment file paths for a raw image
pub fn get_segment_paths(path: &str) -> Result<Vec<PathBuf>, String> {
    let (segments, _) = discover_segments(path)?;
    Ok(segments)
}

/// Extract raw image to a single file (useful for reassembling multi-segment)
pub fn extract(path: &str, output_path: &str) -> Result<(), String> {
    use std::io::Write;
    
    let mut handle = RawHandle::open(path)?;
    let mut output = File::create(output_path)
        .map_err(|e| format!("Failed to create output file: {}", e))?;

    let mut buf = vec![0u8; BUFFER_SIZE];
    
    loop {
        let bytes_read = handle.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }
        output.write_all(&buf[..bytes_read])
            .map_err(|e| format!("Write failed: {}", e))?;
    }

    Ok(())
}

// =============================================================================
// Helper Functions  
// =============================================================================

/// Discover all segments for a raw image - uses common segment discovery
fn discover_segments(path: &str) -> Result<(Vec<std::path::PathBuf>, Vec<u64>), String> {
    trace!(path, "Discovering raw image segments");
    discover_numbered_segments(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_raw() {
        assert!(is_raw("/path/to/image.dd").unwrap());
        assert!(is_raw("/path/to/image.raw").unwrap());
        assert!(is_raw("/path/to/image.img").unwrap());
        assert!(is_raw("/path/to/image.001").unwrap());
        assert!(is_raw("/path/to/image.002").unwrap());
        assert!(!is_raw("/path/to/image.e01").unwrap());
        assert!(!is_raw("/path/to/image.ad1").unwrap());
    }
}
