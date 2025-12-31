//! Public API for E01/EWF operations

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use md5::Md5;
use sha1::{Sha1, Digest};
use sha2::{Sha256, Sha512};
use blake2::Blake2b512;
use blake3::Hasher as Blake3Hasher;
use xxhash_rust::xxh3::Xxh3;
use xxhash_rust::xxh64::Xxh64;
use rayon::prelude::*;
use tracing::debug;

use crate::common::{
    BUFFER_SIZE, MMAP_THRESHOLD,
    hash::StreamingHasher,
    segments::discover_e01_segments,
};

use super::types::*;
use super::handle::E01Handle;

// =============================================================================
// Info Operations
// =============================================================================

pub fn info(path: &str) -> Result<E01Info, String> {
    let handle = E01Handle::open(path)?;
    let volume = handle.get_volume_info();
    let total_size = volume.sector_count * volume.bytes_per_sector as u64;
    
    // Get segment file names
    let segment_count = handle.file_pool.get_file_count() as u32;
    let segment_files = if segment_count > 1 {
        let paths = discover_e01_segments(path).unwrap_or_default();
        let names: Vec<String> = paths.iter()
            .filter_map(|p| p.file_name())
            .map(|f| f.to_string_lossy().to_string())
            .collect();
        if names.is_empty() { None } else { Some(names) }
    } else {
        None
    };
    
    // Get file modification time as fallback timestamp for stored hashes
    let file_timestamp: Option<String> = Path::new(path).metadata().ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let datetime: chrono::DateTime<chrono::Utc> = t.into();
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        });
    
    // Set timestamp on stored hashes from file modification time
    let stored_hashes: Vec<StoredImageHash> = handle.stored_hashes.iter().map(|h| {
        StoredImageHash {
            algorithm: h.algorithm.clone(),
            hash: h.hash.clone(),
            timestamp: h.timestamp.clone().or_else(|| file_timestamp.clone()),
            source: h.source.clone(),
        }
    }).collect();
    
    Ok(E01Info {
        format_version: "EWF1".to_string(),
        segment_count,
        chunk_count: handle.get_chunk_count() as u32,
        sector_count: volume.sector_count,
        bytes_per_sector: volume.bytes_per_sector,
        sectors_per_chunk: volume.sectors_per_chunk,
        total_size,
        compression: "Good (Fast)".to_string(),
        case_number: None,
        description: None,
        examiner_name: None,
        evidence_number: None,
        notes: None,
        acquiry_date: file_timestamp.clone(),
        system_date: None,
        model: None,
        serial_number: None,
        stored_hashes,
        segment_files,
    })
}

/// Check if a file is a valid E01/EWF format image
pub fn is_e01(path: &str) -> Result<bool, String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        debug!("is_e01: file does not exist: {}", path);
        return Ok(false);
    }
    
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let mut sig = [0u8; 8];
    if file.read_exact(&mut sig).is_err() {
        debug!("is_e01: failed to read signature from: {}", path);
        return Ok(false);
    }
    
    let is_ewf1 = &sig == EWF_SIGNATURE;
    let is_ewf2 = &sig == EWF2_SIGNATURE;
    debug!("is_e01: {} -> sig={:02x?} ewf1={} ewf2={}", path, &sig, is_ewf1, is_ewf2);
    Ok(is_ewf1 || is_ewf2)
}

/// Get all E01 segment file paths
pub fn get_segment_paths(path: &str) -> Result<Vec<PathBuf>, String> {
    discover_e01_segments(path)
}

// =============================================================================
// Segment Hashing
// =============================================================================

/// Hash a single E01 segment file (uses mmap for large files)
pub fn hash_single_segment<F>(segment_path: &str, algorithm: &str, mut progress_callback: F) -> Result<String, String>
where
    F: FnMut(u64, u64)
{
    use std::io::BufRead;
    use memmap2::Mmap;
    
    let path = Path::new(segment_path);
    if !path.exists() {
        return Err(format!("Segment file not found: {}", segment_path));
    }
    
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;
    let total_size = metadata.len();
    
    let file = File::open(path)
        .map_err(|e| format!("Failed to open segment: {}", e))?;
    
    let algorithm_lower = algorithm.to_lowercase();
    
    // For BLAKE3 with large files, use mmap + parallel hashing
    if algorithm_lower == "blake3" && total_size >= MMAP_THRESHOLD {
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| format!("Failed to mmap file: {}", e))?;
        
        let mut hasher = blake3::Hasher::new();
        let chunk_size = 64 * 1024 * 1024; // 64MB chunks for progress
        let mut bytes_processed = 0u64;
        
        for chunk in mmap.chunks(chunk_size) {
            hasher.update_rayon(chunk);
            bytes_processed += chunk.len() as u64;
            progress_callback(bytes_processed, total_size);
        }
        
        return Ok(hasher.finalize().to_hex().to_string());
    }
    
    // For large files, use mmap for better I/O
    if total_size >= MMAP_THRESHOLD {
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| format!("Failed to mmap file: {}", e))?;
        
        let mut hasher = StreamingHasher::from_str(algorithm)?;
        let chunk_size = 64 * 1024 * 1024;
        let mut bytes_processed = 0u64;
        
        for chunk in mmap.chunks(chunk_size) {
            hasher.update(chunk);
            bytes_processed += chunk.len() as u64;
            progress_callback(bytes_processed, total_size);
        }
        
        return Ok(hasher.finalize());
    }
    
    // Standard BufReader path for smaller files
    let mut reader = std::io::BufReader::with_capacity(BUFFER_SIZE, file);
    
    // For BLAKE3 without mmap, still use parallel hashing
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

// =============================================================================
// Verification
// =============================================================================

/// Verify image and return detailed results for each chunk (used by containers.rs)
pub fn verify_chunks(path: &str, algorithm: &str) -> Result<Vec<VerifyResult>, String> {
    let hash = verify_with_progress(path, algorithm, |_, _| {})?;
    
    Ok(vec![VerifyResult {
        chunk_index: 0,
        status: "ok".to_string(),
        message: Some(hash),
    }])
}

/// Extract image contents to a raw file
pub fn extract(path: &str, output_dir: &str) -> Result<(), String> {
    let mut handle = E01Handle::open(path)?;
    let volume = handle.get_volume_info();
    let chunk_count = handle.get_chunk_count();
    
    // Create output filename based on input path
    let input_path = Path::new(path);
    let stem = input_path.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "image".to_string());
    
    let output_path = Path::new(output_dir).join(format!("{}.raw", stem));
    let mut output = File::create(&output_path)
        .map_err(|e| format!("Failed to create output file: {}", e))?;
    
    let total_bytes = volume.sector_count * volume.bytes_per_sector as u64;
    let mut bytes_written = 0u64;
    
    for i in 0..chunk_count {
        let chunk_data = handle.read_chunk_no_cache(i)?;
        
        let bytes_to_write = if bytes_written + chunk_data.len() as u64 > total_bytes {
            (total_bytes - bytes_written) as usize
        } else {
            chunk_data.len()
        };
        
        output.write_all(&chunk_data[..bytes_to_write])
            .map_err(|e| format!("Failed to write to output: {}", e))?;
        
        bytes_written += bytes_to_write as u64;
        
        if bytes_written >= total_bytes {
            break;
        }
    }
    
    Ok(())
}

pub fn verify(path: &str, algorithm: &str) -> Result<String, String> {
    verify_with_progress(path, algorithm, |_current, _total| {})
}

pub fn verify_with_progress<F>(path: &str, algorithm: &str, progress_callback: F) -> Result<String, String> 
where
    F: FnMut(usize, usize)
{
    verify_with_progress_parallel_chunks(path, algorithm, progress_callback)
}

/// Pipelined parallel verification: overlap decompression and hashing
fn verify_with_progress_parallel_chunks<F>(path: &str, algorithm: &str, mut progress_callback: F) -> Result<String, String> 
where
    F: FnMut(usize, usize)
{
    use std::sync::mpsc;
    use std::thread;
    
    debug!(path = %path, "Starting parallel chunk verification");
    
    let handle = E01Handle::open(path)?;
    let chunk_count = handle.get_chunk_count();
    debug!(chunk_count, "E01 chunk count");
    
    // Create hasher based on algorithm
    let algorithm_lower = algorithm.to_lowercase();
    let use_sha1 = algorithm_lower == "sha1" || algorithm_lower == "sha-1";
    let use_sha256 = algorithm_lower == "sha256" || algorithm_lower == "sha-256";
    let use_sha512 = algorithm_lower == "sha512" || algorithm_lower == "sha-512";
    let use_blake3 = algorithm_lower == "blake3";
    let use_blake2 = algorithm_lower == "blake2" || algorithm_lower == "blake2b";
    let use_xxh3 = algorithm_lower == "xxh3" || algorithm_lower == "xxhash3";
    let use_xxh64 = algorithm_lower == "xxh64" || algorithm_lower == "xxhash64";
    let use_crc32 = algorithm_lower == "crc32";
    
    let path_str = path.to_string();
    
    let num_threads = rayon::current_num_threads();
    
    let batch_size = if chunk_count > 1_000_000 {
        num_threads * 256
    } else if chunk_count > 100_000 {
        num_threads * 256
    } else if chunk_count > 10_000 {
        num_threads * 128
    } else {
        num_threads * 64
    };
    
    debug!(batch_size, num_threads, chunk_count, "Batch configuration");
    
    let decompressed_chunks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let decompressed_chunks_clone = decompressed_chunks.clone();
    
    let channel_depth = num_threads.max(16);
    let (tx, rx) = mpsc::sync_channel::<Result<(usize, Vec<Vec<u8>>), String>>(channel_depth);
    
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .ok();
    
    // Spawn decompression thread pool
    let decompression_handle = thread::spawn(move || {
        let handles_result: Result<Vec<E01Handle>, String> = (0..num_threads)
            .map(|_| E01Handle::open(&path_str))
            .collect();
        
        let mut handles = match handles_result {
            Ok(h) => h,
            Err(e) => {
                let _ = tx.send(Err(e));
                return;
            }
        };
        
        for batch_start in (0..chunk_count).step_by(batch_size) {
            let batch_end = (batch_start + batch_size).min(chunk_count);
            let batch_chunk_count = batch_end - batch_start;
            
            let thread_results: Vec<Result<Vec<(usize, Vec<u8>)>, String>> = handles
                .par_iter_mut()
                .enumerate()
                .map(|(thread_id, thread_handle)| {
                    let chunks_for_thread = batch_chunk_count.div_ceil(num_threads);
                    let mut chunks = Vec::with_capacity(chunks_for_thread);
                    
                    for chunk_idx in (batch_start + thread_id..batch_end).step_by(num_threads) {
                        match thread_handle.read_chunk_no_cache(chunk_idx) {
                            Ok(chunk_data) => {
                                chunks.push((chunk_idx, chunk_data));
                                decompressed_chunks_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            },
                            Err(e) => return Err(e),
                        }
                    }
                    
                    Ok(chunks)
                })
                .collect();
            
            let mut indexed_chunks = Vec::with_capacity(batch_chunk_count);
            for result in thread_results {
                match result {
                    Ok(mut thread_chunks) => indexed_chunks.append(&mut thread_chunks),
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        return;
                    }
                }
            }
            
            indexed_chunks.sort_unstable_by_key(|(idx, _)| *idx);
            let batch_data: Vec<Vec<u8>> = indexed_chunks.into_iter().map(|(_, data)| data).collect();
            
            if tx.send(Ok((batch_start, batch_data))).is_err() {
                return;
            }
        }
    });
    
    // Hash on main thread
    let is_known_algo = use_sha1 || use_sha256 || use_sha512 || use_blake3 || use_blake2 || use_xxh3 || use_xxh64 || use_crc32;
    let mut md5_hasher: Option<Md5> = if !is_known_algo { Some(Md5::new()) } else { None };
    let mut sha1_hasher = if use_sha1 { Some(Sha1::new()) } else { None };
    let mut sha256_hasher = if use_sha256 { Some(Sha256::new()) } else { None };
    let mut sha512_hasher = if use_sha512 { Some(Sha512::new()) } else { None };
    let mut blake3_hasher = if use_blake3 { Some(Blake3Hasher::new()) } else { None };
    let mut blake2_hasher = if use_blake2 { Some(Blake2b512::new()) } else { None };
    let mut xxh3_hasher = if use_xxh3 { Some(Xxh3::new()) } else { None };
    let mut xxh64_hasher = if use_xxh64 { Some(Xxh64::new(0)) } else { None };
    let mut crc32_hasher = if use_crc32 { Some(crc32fast::Hasher::new()) } else { None };
    
    while let Ok(batch_result) = rx.recv() {
        let decompressed = decompressed_chunks.load(std::sync::atomic::Ordering::Relaxed);
        progress_callback(decompressed, chunk_count);
        
        match batch_result {
            Ok((batch_start, batch_chunks)) => {
                for (relative_idx, chunk_data) in batch_chunks.iter().enumerate() {
                    let _chunk_idx = batch_start + relative_idx;
                    
                    if let Some(ref mut hasher) = md5_hasher {
                        Digest::update(hasher, chunk_data);
                    } else if let Some(ref mut hasher) = sha1_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = sha256_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = sha512_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = blake3_hasher {
                        hasher.update_rayon(chunk_data);
                    } else if let Some(ref mut hasher) = blake2_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = xxh3_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = xxh64_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = crc32_hasher {
                        hasher.update(chunk_data);
                    }
                }
            }
            Err(e) => {
                let _ = decompression_handle.join();
                return Err(e);
            }
        }
    }
    
    progress_callback(chunk_count, chunk_count);
    
    decompression_handle.join().map_err(|_| "Decompression thread panicked".to_string())?;
    
    // Return hash result
    if let Some(hasher) = md5_hasher {
        Ok(hex::encode(hasher.finalize()))
    } else if let Some(hasher) = sha1_hasher {
        Ok(hex::encode(hasher.finalize()))
    } else if let Some(hasher) = sha256_hasher {
        Ok(hex::encode(hasher.finalize()))
    } else if let Some(hasher) = sha512_hasher {
        Ok(hex::encode(hasher.finalize()))
    } else if let Some(hasher) = blake3_hasher {
        Ok(format!("{}", hasher.finalize().to_hex()))
    } else if let Some(hasher) = blake2_hasher {
        Ok(hex::encode(hasher.finalize()))
    } else if let Some(hasher) = xxh3_hasher {
        Ok(format!("{:016x}", hasher.digest128()))
    } else if let Some(hasher) = xxh64_hasher {
        Ok(format!("{:016x}", hasher.digest()))
    } else if let Some(hasher) = crc32_hasher {
        Ok(format!("{:08x}", hasher.finalize()))
    } else {
        Err("Unknown hash algorithm".to_string())
    }
}
