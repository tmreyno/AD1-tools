// RAW disk image parser (.dd, .raw, .img, .001, .002, etc.)
// Supports single and multi-segment raw forensic images

use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::{Sha256, Sha512};
use blake2::Blake2b512;
use blake3::Hasher as Blake3Hasher;

const BUFFER_SIZE: usize = 64 * 1024; // 64KB read buffer

// =============================================================================
// Public Types
// =============================================================================

#[derive(Serialize, Clone)]
pub struct RawInfo {
    pub segment_count: u32,
    pub total_size: u64,
    pub segment_sizes: Vec<u64>,
    pub first_segment: String,
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
    
    Ok(RawInfo {
        segment_count: handle.segment_count() as u32,
        total_size: handle.total_size(),
        segment_sizes: handle.segment_sizes.clone(),
        first_segment: handle.segments.first()
            .map(|p| p.to_string_lossy().to_string())
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

/// Verify with progress callback
pub fn verify_with_progress<F>(path: &str, algorithm: &str, mut progress_callback: F) -> Result<String, String>
where
    F: FnMut(u64, u64)
{
    let mut handle = RawHandle::open(path)?;
    let total_size = handle.total_size();
    let algorithm_lower = algorithm.to_lowercase();

    // Select hasher based on algorithm
    let use_md5 = algorithm_lower == "md5";
    let use_sha1 = algorithm_lower == "sha1" || algorithm_lower == "sha-1";
    let use_sha256 = algorithm_lower == "sha256" || algorithm_lower == "sha-256";
    let use_sha512 = algorithm_lower == "sha512" || algorithm_lower == "sha-512";
    let use_blake3 = algorithm_lower == "blake3";
    let use_blake2 = algorithm_lower == "blake2" || algorithm_lower == "blake2b";

    if !use_md5 && !use_sha1 && !use_sha256 && !use_sha512 && !use_blake3 && !use_blake2 {
        return Err(format!("Unsupported algorithm: {}. Supported: md5, sha1, sha256, sha512, blake3, blake2", algorithm));
    }

    // Initialize hashers
    let mut md5_hasher = if use_md5 { Some(md5::Context::new()) } else { None };
    let mut sha1_hasher = if use_sha1 { Some(Sha1::new()) } else { None };
    let mut sha256_hasher = if use_sha256 { Some(Sha256::new()) } else { None };
    let mut sha512_hasher = if use_sha512 { Some(Sha512::new()) } else { None };
    let mut blake3_hasher = if use_blake3 { Some(Blake3Hasher::new()) } else { None };
    let mut blake2_hasher = if use_blake2 { Some(Blake2b512::new()) } else { None };

    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut bytes_read_total = 0u64;
    let report_interval = total_size / 100; // Report every 1%

    loop {
        let bytes_read = handle.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }

        let data = &buf[..bytes_read];

        // Update appropriate hasher
        if let Some(ref mut h) = md5_hasher { h.consume(data); }
        if let Some(ref mut h) = sha1_hasher { h.update(data); }
        if let Some(ref mut h) = sha256_hasher { h.update(data); }
        if let Some(ref mut h) = sha512_hasher { h.update(data); }
        if let Some(ref mut h) = blake3_hasher { h.update(data); }
        if let Some(ref mut h) = blake2_hasher { 
            use blake2::Digest;
            h.update(data); 
        }

        bytes_read_total += bytes_read as u64;

        // Progress callback
        if bytes_read_total % report_interval.max(1) < BUFFER_SIZE as u64 {
            progress_callback(bytes_read_total, total_size);
        }
    }

    // Final progress
    progress_callback(total_size, total_size);

    // Return hash result
    if let Some(h) = md5_hasher {
        Ok(format!("{:x}", h.compute()))
    } else if let Some(h) = sha1_hasher {
        Ok(hex::encode(h.finalize()))
    } else if let Some(h) = sha256_hasher {
        Ok(hex::encode(h.finalize()))
    } else if let Some(h) = sha512_hasher {
        Ok(hex::encode(h.finalize()))
    } else if let Some(h) = blake3_hasher {
        Ok(h.finalize().to_hex().to_string())
    } else if let Some(h) = blake2_hasher {
        use blake2::Digest;
        Ok(hex::encode(h.finalize()))
    } else {
        Err("No hasher initialized".to_string())
    }
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
fn discover_numbered_segments(dir: &Path, base: &str) -> Result<(Vec<PathBuf>, Vec<u64>), String> {
    let mut segments = Vec::new();
    let mut sizes = Vec::new();

    for num in 1..=999 {
        let segment_name = format!("{}.{:03}", base, num);
        let segment_path = dir.join(&segment_name);
        
        if !segment_path.exists() {
            // Also try lowercase
            let segment_name_lower = segment_name.to_lowercase();
            let segment_path_lower = dir.join(&segment_name_lower);
            
            if !segment_path_lower.exists() {
                break; // No more segments
            }
            
            let size = std::fs::metadata(&segment_path_lower)
                .map_err(|e| format!("Failed to get segment size: {}", e))?
                .len();
            segments.push(segment_path_lower);
            sizes.push(size);
        } else {
            let size = std::fs::metadata(&segment_path)
                .map_err(|e| format!("Failed to get segment size: {}", e))?
                .len();
            segments.push(segment_path);
            sizes.push(size);
        }
    }

    if segments.is_empty() {
        return Err("No segments found".to_string());
    }

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
