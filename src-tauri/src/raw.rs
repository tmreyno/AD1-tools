// RAW disk image parser (.dd, .raw, .img, .001, .002, etc.)
// Supports single and multi-segment raw forensic images

use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, BufReader};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use crate::common::{BUFFER_SIZE, hash::StreamingHasher};

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
pub fn info(path: &str) -> Result<RawInfo, String> {
    let handle = RawHandle::open(path)?;
    
    // Extract just filenames for display
    let segment_names: Vec<String> = handle.segments.iter()
        .map(|p| p.file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default())
        .collect();
    
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
pub fn verify_with_progress<F>(path: &str, algorithm: &str, progress_callback: F) -> Result<String, String>
where
    F: FnMut(u64, u64)
{
    let handle = RawHandle::open(path)?;
    let total_size = handle.total_size();
    let algorithm_lower = algorithm.to_lowercase();

    // Validate algorithm
    let valid_algo = matches!(algorithm_lower.as_str(), 
        "md5" | "sha1" | "sha-1" | "sha256" | "sha-256" | 
        "sha512" | "sha-512" | "blake3" | "blake2" | "blake2b");
    
    if !valid_algo {
        return Err(format!("Unsupported algorithm: {}. Supported: md5, sha1, sha256, sha512, blake3, blake2", algorithm));
    }

    // For BLAKE3, use its built-in parallel hashing with memory-mapped I/O
    if algorithm_lower == "blake3" {
        return verify_blake3_optimized(path, total_size, progress_callback);
    }

    // For other algorithms, use pipelined I/O -> hashing
    verify_pipelined(path, &algorithm_lower, total_size, progress_callback)
}

/// BLAKE3 optimized path - uses rayon-based parallel hashing
fn verify_blake3_optimized<F>(path: &str, total_size: u64, mut progress_callback: F) -> Result<String, String>
where
    F: FnMut(u64, u64)
{
    use std::io::BufRead;
    
    let mut hasher = blake3::Hasher::new();
    let segments = discover_segments(path)?.0;
    let mut bytes_processed = 0u64;
    let report_interval = (total_size / 50).max(BUFFER_SIZE as u64); // Report ~50 times
    let mut last_report = 0u64;
    
    for seg_path in &segments {
        let file = File::open(seg_path)
            .map_err(|e| format!("Failed to open segment: {}", e))?;
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
        
        loop {
            let buf = reader.fill_buf()
                .map_err(|e| format!("Read error: {}", e))?;
            let len = buf.len();
            if len == 0 { break; }
            
            // BLAKE3 update_rayon uses all cores for parallel hashing
            hasher.update_rayon(buf);
            reader.consume(len);
            
            bytes_processed += len as u64;
            if bytes_processed - last_report >= report_interval {
                progress_callback(bytes_processed, total_size);
                last_report = bytes_processed;
            }
        }
    }
    
    progress_callback(total_size, total_size);
    Ok(hasher.finalize().to_hex().to_string())
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
    
    let file = File::open(path)
        .map_err(|e| format!("Failed to open segment: {}", e))?;
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
    
    let algorithm_lower = algorithm.to_lowercase();
    
    // For BLAKE3, use parallel hashing for best performance
    if algorithm_lower == "blake3" {
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
        return Ok(hasher.finalize().to_hex().to_string());
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

/// Discover all segments for a raw image
fn discover_segments(path: &str) -> Result<(Vec<PathBuf>, Vec<u64>), String> {
    let path_obj = Path::new(path);
    let parent = path_obj.parent().unwrap_or(Path::new("."));
    let filename = path_obj.file_name()
        .ok_or("Invalid filename")?
        .to_string_lossy();

    let lower = filename.to_lowercase();
    
    // Check if this is a numbered segment (.001, .002, etc.)
    if let Some(ext_start) = lower.rfind('.') {
        let ext = &lower[ext_start + 1..];
        if ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()) {
            // Multi-segment numbered format
            let base = &filename[..filename.len() - 4]; // Remove .XXX
            return discover_numbered_segments(parent, base);
        }
    }

    // Single file or other format - just use the one file
    let size = std::fs::metadata(path)
        .map_err(|e| format!("Failed to get file size: {}", e))?
        .len();
    
    Ok((vec![path_obj.to_path_buf()], vec![size]))
}

/// Discover numbered segments (.001, .002, etc.)
/// Handles cases where segments might start from a number other than 001
fn discover_numbered_segments(dir: &Path, base: &str) -> Result<(Vec<PathBuf>, Vec<u64>), String> {
    // First try direct path construction
    let result = discover_numbered_segments_direct(dir, base);
    if let Ok((segs, _)) = &result {
        if !segs.is_empty() {
            return result;
        }
    }
    
    // Fall back to directory scan for case-insensitive matching
    discover_numbered_segments_scan(dir, base)
}

/// Try to find segments by constructing paths directly
fn discover_numbered_segments_direct(dir: &Path, base: &str) -> Result<(Vec<PathBuf>, Vec<u64>), String> {
    let mut segments = Vec::new();
    let mut sizes = Vec::new();
    let mut found_any = false;
    let mut consecutive_missing = 0;

    for num in 1..=999 {
        let segment_name = format!("{}.{:03}", base, num);
        let segment_path = dir.join(&segment_name);
        
        // Try original case first
        if segment_path.exists() {
            let size = std::fs::metadata(&segment_path)
                .map_err(|e| format!("Failed to get segment size: {}", e))?
                .len();
            segments.push(segment_path);
            sizes.push(size);
            found_any = true;
            consecutive_missing = 0;
            continue;
        }
        
        // Try lowercase
        let segment_name_lower = segment_name.to_lowercase();
        let segment_path_lower = dir.join(&segment_name_lower);
        if segment_path_lower.exists() {
            let size = std::fs::metadata(&segment_path_lower)
                .map_err(|e| format!("Failed to get segment size: {}", e))?
                .len();
            segments.push(segment_path_lower);
            sizes.push(size);
            found_any = true;
            consecutive_missing = 0;
            continue;
        }
        
        // Try uppercase
        let segment_name_upper = segment_name.to_uppercase();
        let segment_path_upper = dir.join(&segment_name_upper);
        if segment_path_upper.exists() {
            let size = std::fs::metadata(&segment_path_upper)
                .map_err(|e| format!("Failed to get segment size: {}", e))?
                .len();
            segments.push(segment_path_upper);
            sizes.push(size);
            found_any = true;
            consecutive_missing = 0;
            continue;
        }
        
        // Segment not found
        consecutive_missing += 1;
        
        // If we've found segments before and now have a gap, stop
        if found_any {
            break; // End of sequence
        } else if consecutive_missing > 10 {
            // Haven't found any and checked first 10 numbers - give up
            break;
        }
    }

    Ok((segments, sizes))
}

/// Scan directory to find segments with case-insensitive matching
fn discover_numbered_segments_scan(dir: &Path, base: &str) -> Result<(Vec<PathBuf>, Vec<u64>), String> {
    let base_lower = base.to_lowercase();
    let mut found_segments: Vec<(u32, PathBuf, u64)> = Vec::new();
    
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let filename = entry.file_name().to_string_lossy().to_string();
            let filename_lower = filename.to_lowercase();
            
            // Check if filename matches our pattern (base.XXX where XXX is numeric)
            if let Some(dot_pos) = filename_lower.rfind('.') {
                let file_base = &filename_lower[..dot_pos];
                let ext = &filename_lower[dot_pos + 1..];
                
                if file_base == base_lower && ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()) {
                    if let Ok(num) = ext.parse::<u32>() {
                        if let Ok(meta) = entry.metadata() {
                            found_segments.push((num, entry.path(), meta.len()));
                        }
                    }
                }
            }
        }
    }
    
    if found_segments.is_empty() {
        return Err("No segments found".to_string());
    }
    
    // Sort by segment number
    found_segments.sort_by_key(|(num, _, _)| *num);
    
    let segments: Vec<PathBuf> = found_segments.iter().map(|(_, p, _)| p.clone()).collect();
    let sizes: Vec<u64> = found_segments.iter().map(|(_, _, s)| *s).collect();
    
    Ok((segments, sizes))
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
