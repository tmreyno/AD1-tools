//! FFX - Forensic File Xplorer Library
//!
//! This library provides parsing, verification, and extraction capabilities
//! for forensic disk image and logical evidence container formats.
//!
//! ## Supported Formats
//!
//! | Format | Module    | Description                                    |
//! |--------|-----------|------------------------------------------------|
//! | AD1    | `ad1`     | AccessData Logical Image (FTK)                 |
//! | E01    | `ewf`     | Expert Witness Format / EnCase                 |
//! | L01    | `l01`     | EnCase Logical Evidence File                   |
//! | RAW    | `raw`     | dd-style images (.dd, .raw, .img, .001)        |
//! | 7z     | `archive` | 7-Zip archives (metadata only)                 |
//! | ZIP    | `archive` | ZIP/ZIP64 archives (metadata only)             |
//! | RAR    | `archive` | RAR4/RAR5 archives (metadata only)             |
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Tauri Commands (lib.rs)                                    │
//! │   - logical_info, logical_verify, logical_extract           │
//! │   - scan_directory, scan_directory_streaming                │
//! │   - e01_v3_*, raw_*, raw_verify_segments                    │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Container Abstraction (containers.rs)                      │
//! │   - ContainerInfo, ContainerKind                            │
//! │   - Auto-detection by signature and extension               │
//! │   - Unified info/verify/extract interface                   │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Format Parsers                                             │
//! │   ┌─────────┬─────────┬─────────┬─────────┬─────────┐      │
//! │   │  ad1.rs │  ewf.rs │  l01.rs │  raw.rs │archive.rs│     │
//! │   └─────────┴─────────┴─────────┴─────────┴─────────┘      │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Common Utilities (common/)                                 │
//! │   - hash.rs:     Streaming hashers (SHA, BLAKE3, XXH3)     │
//! │   - binary.rs:   Little-endian binary reading              │
//! │   - segments.rs: Multi-segment file discovery              │
//! │   - io_pool.rs:  File handle pooling                       │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Tauri Integration
//!
//! All parsing operations run on blocking threads to prevent UI freezing.
//! Progress events are emitted via Tauri's event system:
//!
//! - `scan-file-found`: File discovered during directory scan
//! - `verify-progress`: Hash verification progress (current, total, percent)
//! - `segment-verify-progress`: Per-segment verification progress
//!
//! ## Performance Considerations
//!
//! - **Streaming I/O**: Large files use buffered/memory-mapped I/O
//! - **Parallel hashing**: BLAKE3 uses rayon for parallel processing
//! - **Pipelined I/O**: Separate reader/hasher threads for throughput
//! - **LRU caching**: AD1 decompressed blocks cached for random access
//!
//! ## Forensic Standards Compliance
//!
//! This library prioritizes forensic correctness:
//! - Read-only operations (never modifies source files)
//! - Hash verification against stored checksums
//! - Companion log parsing for chain-of-custody metadata
//! - Byte-accurate extraction preserving timestamps

mod ad1;
pub mod archive;  // Archive formats (7z, ZIP, RAR, etc.)
pub mod common;  // Shared utilities (hash, binary, segments)
pub mod ewf;  // Expert Witness Format (E01/EWF/Ex01) parser
mod l01;
pub mod logging;  // Logging and tracing configuration
pub mod raw;  // Raw disk images (.dd, .raw, .img, .001, etc.)
mod containers;

use tauri::Emitter;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::thread;
use tracing::{debug, info, instrument};

#[tauri::command]
fn logical_info(
    #[allow(non_snake_case)]
    inputPath: String,
    #[allow(non_snake_case)]
    includeTree: bool,
) -> Result<containers::ContainerInfo, String> {
    containers::info(&inputPath, includeTree)
}

/// Fast info - only reads headers, doesn't parse full item trees
/// Use this for quick container listing/display
#[tauri::command]
fn logical_info_fast(
    #[allow(non_snake_case)]
    inputPath: String,
) -> Result<containers::ContainerInfo, String> {
    containers::info_fast(&inputPath)
}

#[tauri::command]
fn logical_verify(
    #[allow(non_snake_case)]
    inputPath: String,
    algorithm: String,
) -> Result<Vec<containers::VerifyEntry>, String> {
    containers::verify(&inputPath, &algorithm)
}

#[tauri::command]
fn logical_extract(
    #[allow(non_snake_case)]
    inputPath: String,
    #[allow(non_snake_case)]
    outputDir: String,
) -> Result<(), String> {
    containers::extract(&inputPath, &outputDir)
}

#[tauri::command]
fn scan_directory(
    #[allow(non_snake_case)]
    dirPath: String,
) -> Result<Vec<containers::DiscoveredFile>, String> {
    containers::scan_directory(&dirPath)
}

#[tauri::command]
fn scan_directory_recursive(
    #[allow(non_snake_case)]
    dirPath: String,
) -> Result<Vec<containers::DiscoveredFile>, String> {
    containers::scan_directory_recursive(&dirPath)
}

#[tauri::command]
#[instrument(skip(window), fields(path = %dirPath, recursive))]
async fn scan_directory_streaming(
    window: tauri::Window,
    #[allow(non_snake_case)]
    dirPath: String,
    recursive: bool,
) -> Result<usize, String> {
    use tokio::sync::mpsc;
    
    info!("Starting directory scan");
    let (tx, mut rx) = mpsc::unbounded_channel::<containers::DiscoveredFile>();
    
    // Spawn blocking directory scan in background thread
    let dir_path_clone = dirPath.clone();
    let scan_handle = tauri::async_runtime::spawn_blocking(move || {
        containers::scan_directory_streaming(&dir_path_clone, recursive, |file| {
            let _ = tx.send(file.clone());
        })
    });
    
    // Stream results to frontend as they arrive
    let mut emitted = 0usize;
    while let Some(file) = rx.recv().await {
        debug!(file = %file.filename, "Found file");
        let _ = window.emit("scan-file-found", &file);
        emitted += 1;
    }
    
    // Wait for scan to complete and return count
    let result = scan_handle.await.map_err(|e| format!("Task failed: {e}"))?;
    info!(count = emitted, "Scan complete");
    result
}

// EWF Commands - Expert Witness Format implementation
#[tauri::command]
async fn e01_v3_info(
    #[allow(non_snake_case)]
    inputPath: String,
) -> Result<ewf::E01Info, String> {
    // Run on blocking thread pool to prevent UI freeze during file parsing
    tauri::async_runtime::spawn_blocking(move || {
        ewf::info(&inputPath)
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))?
}

#[derive(Clone, serde::Serialize)]
struct VerifyProgress {
    current: usize,
    total: usize,
    percent: f64,
}

#[tauri::command]
async fn e01_v3_verify(
    #[allow(non_snake_case)]
    inputPath: String,
    algorithm: String,
    app: tauri::AppHandle,
) -> Result<String, String> {
    // Run on blocking thread pool to prevent UI freeze
    tauri::async_runtime::spawn_blocking(move || {
        ewf::verify_with_progress(&inputPath, &algorithm, |current, total| {
            let percent = (current as f64 / total as f64) * 100.0;
            let _ = app.emit("verify-progress", VerifyProgress {
                current,
                total,
                percent,
            });
        })
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))?
}

// RAW Commands - Raw disk image implementation (.dd, .raw, .img, .001)
#[tauri::command]
async fn raw_info(
    #[allow(non_snake_case)]
    inputPath: String,
) -> Result<raw::RawInfo, String> {
    tauri::async_runtime::spawn_blocking(move || {
        raw::info(&inputPath)
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))?
}

#[tauri::command]
async fn raw_verify(
    #[allow(non_snake_case)]
    inputPath: String,
    algorithm: String,
    app: tauri::AppHandle,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        raw::verify_with_progress(&inputPath, &algorithm, |current, total| {
            let percent = (current as f64 / total as f64) * 100.0;
            let _ = app.emit("verify-progress", VerifyProgress {
                current: current as usize,
                total: total as usize,
                percent,
            });
        })
    })
    .await
    .map_err(|e| format!("Task failed: {}", e))?
}

/// Verify individual segments of a raw image, comparing against stored hashes
#[derive(Clone, serde::Serialize)]
struct SegmentVerifyProgress {
    segment_name: String,
    segment_number: u32,
    percent: f64,
    segments_completed: usize,
    segments_total: usize,
}

#[derive(Clone, serde::Serialize)]
struct SegmentHashResult {
    segment_name: String,
    segment_number: u32,
    segment_path: String,
    algorithm: String,
    computed_hash: String,
    expected_hash: Option<String>,
    verified: Option<bool>,  // None = no expected, true = match, false = mismatch
    size: u64,
    duration_secs: f64,
}

#[tauri::command]
async fn raw_verify_segments(
    #[allow(non_snake_case)]
    inputPath: String,
    algorithm: String,
    #[allow(non_snake_case)]
    expectedHashes: Vec<containers::SegmentHash>,  // Optional: stored hashes from companion log
    app: tauri::AppHandle,
) -> Result<Vec<SegmentHashResult>, String> {
    use std::sync::Mutex;
    use std::time::Instant;
    
    // Get all segment paths
    let segment_paths = raw::get_segment_paths(&inputPath)?;
    let num_segments = segment_paths.len();
    
    if num_segments == 0 {
        return Err("No segments found".to_string());
    }
    
    // Build expected hash lookup (by segment name, case-insensitive)
    let expected_map: std::collections::HashMap<String, String> = expectedHashes
        .iter()
        .map(|h| (h.segment_name.to_lowercase(), h.hash.clone()))
        .collect();
    
    // Use rayon for parallel processing
    let num_cpus = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let parallelism = num_cpus.min(num_segments);
    
    let segments_completed = Arc::new(AtomicUsize::new(0));
    let results: Arc<Mutex<Vec<SegmentHashResult>>> = Arc::new(Mutex::new(Vec::with_capacity(num_segments)));
    let app = Arc::new(app);
    let algorithm = Arc::new(algorithm);
    let expected_map = Arc::new(expected_map);
    
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(parallelism)
        .build()
        .map_err(|e| format!("Failed to create thread pool: {}", e))?;
    
    pool.scope(|s| {
        for (idx, seg_path) in segment_paths.into_iter().enumerate() {
            let segments_completed = Arc::clone(&segments_completed);
            let results = Arc::clone(&results);
            let app = Arc::clone(&app);
            let algorithm = Arc::clone(&algorithm);
            let expected_map = Arc::clone(&expected_map);
            let segment_number = (idx + 1) as u32;
            
            s.spawn(move |_| {
                let segment_name: String = seg_path.file_name()
                    .map(|f: &std::ffi::OsStr| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| format!("segment_{}", segment_number));
                let seg_path_str = seg_path.to_string_lossy().to_string();
                
                // Emit start event
                let _ = app.emit("segment-verify-progress", SegmentVerifyProgress {
                    segment_name: segment_name.clone(),
                    segment_number,
                    percent: 0.0,
                    segments_completed: segments_completed.load(Ordering::Relaxed),
                    segments_total: num_segments,
                });
                
                let start_time = Instant::now();
                
                // Hash the segment
                let hash_result = raw::hash_single_segment(&seg_path_str, &algorithm, |current, total| {
                    let percent = (current as f64 / total as f64) * 100.0;
                    let _ = app.emit("segment-verify-progress", SegmentVerifyProgress {
                        segment_name: segment_name.clone(),
                        segment_number,
                        percent,
                        segments_completed: segments_completed.load(Ordering::Relaxed),
                        segments_total: num_segments,
                    });
                });
                
                let duration = start_time.elapsed().as_secs_f64();
                let completed = segments_completed.fetch_add(1, Ordering::SeqCst) + 1;
                
                // Get file size
                let size = std::fs::metadata(&seg_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                
                match hash_result {
                    Ok(computed_hash) => {
                        // Look up expected hash
                        let expected_hash = expected_map.get(&segment_name.to_lowercase()).cloned();
                        let verified = expected_hash.as_ref().map(|expected| {
                            computed_hash.to_lowercase() == expected.to_lowercase()
                        });
                        
                        let _ = app.emit("segment-verify-progress", SegmentVerifyProgress {
                            segment_name: segment_name.clone(),
                            segment_number,
                            percent: 100.0,
                            segments_completed: completed,
                            segments_total: num_segments,
                        });
                        
                        results.lock().unwrap().push(SegmentHashResult {
                            segment_name,
                            segment_number,
                            segment_path: seg_path_str,
                            algorithm: algorithm.to_uppercase(),
                            computed_hash,
                            expected_hash,
                            verified,
                            size,
                            duration_secs: duration,
                        });
                    }
                    Err(e) => {
                        // Return error result for this segment
                        results.lock().unwrap().push(SegmentHashResult {
                            segment_name,
                            segment_number,
                            segment_path: seg_path_str,
                            algorithm: algorithm.to_uppercase(),
                            computed_hash: format!("ERROR: {}", e),
                            expected_hash: None,
                            verified: None,
                            size,
                            duration_secs: duration,
                        });
                    }
                }
            });
        }
    });
    
    let mut final_results = Arc::try_unwrap(results)
        .map_err(|_| "Failed to unwrap results")?
        .into_inner()
        .map_err(|e| format!("Lock error: {}", e))?;
    
    // Sort by segment number
    final_results.sort_by_key(|r| r.segment_number);
    
    Ok(final_results)
}

/// Verify individual E01 segment files by hashing each .E01, .E02, etc. file
#[tauri::command]
async fn e01_verify_segments(
    #[allow(non_snake_case)]
    inputPath: String,
    algorithm: String,
    #[allow(non_snake_case)]
    expectedHashes: Vec<containers::SegmentHash>,
    app: tauri::AppHandle,
) -> Result<Vec<SegmentHashResult>, String> {
    use std::sync::Mutex;
    use std::time::Instant;
    
    // Get all segment paths
    let segment_paths = ewf::get_segment_paths(&inputPath)?;
    let num_segments = segment_paths.len();
    
    if num_segments == 0 {
        return Err("No E01 segments found".to_string());
    }
    
    // Build expected hash lookup (by segment name, case-insensitive)
    let expected_map: std::collections::HashMap<String, String> = expectedHashes
        .iter()
        .map(|h| (h.segment_name.to_lowercase(), h.hash.clone()))
        .collect();
    
    let num_cpus = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let parallelism = num_cpus.min(num_segments);
    
    let segments_completed = Arc::new(AtomicUsize::new(0));
    let results: Arc<Mutex<Vec<SegmentHashResult>>> = Arc::new(Mutex::new(Vec::with_capacity(num_segments)));
    let app = Arc::new(app);
    let algorithm = Arc::new(algorithm);
    let expected_map = Arc::new(expected_map);
    
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(parallelism)
        .build()
        .map_err(|e| format!("Failed to create thread pool: {}", e))?;
    
    pool.scope(|s| {
        for (idx, seg_path) in segment_paths.into_iter().enumerate() {
            let segments_completed = Arc::clone(&segments_completed);
            let results = Arc::clone(&results);
            let app = Arc::clone(&app);
            let algorithm = Arc::clone(&algorithm);
            let expected_map = Arc::clone(&expected_map);
            let segment_number = (idx + 1) as u32;
            
            s.spawn(move |_| {
                let segment_name: String = seg_path.file_name()
                    .map(|f: &std::ffi::OsStr| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| format!("segment_{}", segment_number));
                let seg_path_str = seg_path.to_string_lossy().to_string();
                
                // Emit start event
                let _ = app.emit("segment-verify-progress", SegmentVerifyProgress {
                    segment_name: segment_name.clone(),
                    segment_number,
                    percent: 0.0,
                    segments_completed: segments_completed.load(Ordering::Relaxed),
                    segments_total: num_segments,
                });
                
                let start_time = Instant::now();
                
                // Hash the segment
                let hash_result = ewf::hash_single_segment(&seg_path_str, &algorithm, |current, total| {
                    let percent = (current as f64 / total as f64) * 100.0;
                    let _ = app.emit("segment-verify-progress", SegmentVerifyProgress {
                        segment_name: segment_name.clone(),
                        segment_number,
                        percent,
                        segments_completed: segments_completed.load(Ordering::Relaxed),
                        segments_total: num_segments,
                    });
                });
                
                let duration = start_time.elapsed().as_secs_f64();
                let completed = segments_completed.fetch_add(1, Ordering::Relaxed) + 1;
                let size = std::fs::metadata(&seg_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                
                match hash_result {
                    Ok(computed_hash) => {
                        let expected_hash = expected_map.get(&segment_name.to_lowercase()).cloned();
                        let verified = expected_hash.as_ref().map(|expected| {
                            computed_hash.to_lowercase() == expected.to_lowercase()
                        });
                        
                        let _ = app.emit("segment-verify-progress", SegmentVerifyProgress {
                            segment_name: segment_name.clone(),
                            segment_number,
                            percent: 100.0,
                            segments_completed: completed,
                            segments_total: num_segments,
                        });
                        
                        results.lock().unwrap().push(SegmentHashResult {
                            segment_name,
                            segment_number,
                            segment_path: seg_path_str,
                            algorithm: algorithm.to_uppercase(),
                            computed_hash,
                            expected_hash,
                            verified,
                            size,
                            duration_secs: duration,
                        });
                    }
                    Err(e) => {
                        results.lock().unwrap().push(SegmentHashResult {
                            segment_name,
                            segment_number,
                            segment_path: seg_path_str,
                            algorithm: algorithm.to_uppercase(),
                            computed_hash: format!("ERROR: {}", e),
                            expected_hash: None,
                            verified: None,
                            size,
                            duration_secs: duration,
                        });
                    }
                }
            });
        }
    });
    
    let mut final_results = Arc::try_unwrap(results)
        .map_err(|_| "Failed to unwrap results")?
        .into_inner()
        .map_err(|e| format!("Lock error: {}", e))?;
    
    final_results.sort_by_key(|r| r.segment_number);
    
    Ok(final_results)
}

// Batch hashing result for a single file
#[derive(Clone, serde::Serialize)]
struct BatchHashResult {
    path: String,
    algorithm: String,
    hash: Option<String>,
    error: Option<String>,
    duration_ms: Option<u64>,
    throughput_mbs: Option<f64>,
}

// Progress update for batch hashing - includes hash result when completed
#[derive(Clone, serde::Serialize)]
struct BatchProgress {
    path: String,
    status: String,  // "started", "progress", "completed", "error"
    percent: f64,
    files_completed: usize,
    files_total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Hash multiple files in parallel with smart scheduling
/// 
/// Optimizations:
/// Simple sequential batch hash - hash files one by one with progress updates
#[tauri::command]
#[instrument(skip(files, app), fields(num_files = files.len(), algorithm = %algorithm))]
async fn batch_hash(
    files: Vec<BatchFileInput>,
    algorithm: String,
    app: tauri::AppHandle,
) -> Result<Vec<BatchHashResult>, String> {
    let num_files = files.len();
    info!("Starting parallel batch hash");
    if num_files == 0 {
        return Ok(Vec::new());
    }
    
    // Determine parallelism based on available CPU cores
    // Use all available cores for maximum throughput
    let num_cpus = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    // Allow processing up to num_cpus files concurrently (or fewer for small batches)
    let max_concurrent = num_cpus.min(num_files);
    debug!(max_concurrent, num_cpus, "Parallel file limit set based on CPU cores");
    
    // Use a semaphore to limit concurrent file processing
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    
    // Spawn all file processing tasks
    let mut handles = Vec::with_capacity(num_files);
    
    for (idx, file) in files.into_iter().enumerate() {
        let path = file.path.clone();
        let container_type = file.container_type.to_lowercase();
        let algo = algorithm.clone();
        let app_clone = app.clone();
        let sem = semaphore.clone();
        
        // Emit progress: queued
        let _ = app.emit("batch-progress", BatchProgress {
            path: path.clone(),
            status: "queued".to_string(),
            percent: 0.0,
            files_completed: 0,
            files_total: num_files,
            hash: None,
            algorithm: None,
            error: None,
        });
        
        let handle = tauri::async_runtime::spawn(async move {
            // Acquire semaphore permit (limits concurrent files)
            let _permit = sem.acquire_owned().await.map_err(|e| format!("Semaphore error: {}", e))?;
            
            debug!(idx = idx + 1, total = num_files, path = %path, "File started");
            
            // Emit progress: started
            let _ = app_clone.emit("batch-progress", BatchProgress {
                path: path.clone(),
                status: "started".to_string(),
                percent: 0.0,
                files_completed: idx,
                files_total: num_files,
                hash: None,
                algorithm: None,
                error: None,
            });
            
            let path_for_hash = path.clone();
            let algo_for_hash = algo.clone();
            let container_for_hash = container_type.clone();
            let app_for_hash = app_clone.clone();
            
            // Run blocking hash in spawn_blocking
            let hash_result = tauri::async_runtime::spawn_blocking(move || {
                let start_time = std::time::Instant::now();
                let file_size = std::fs::metadata(&path_for_hash).map(|m| m.len()).unwrap_or(0);
                debug!(idx = idx + 1, size_mb = file_size / 1024 / 1024, "Processing file");
                
                // Progress counters
                let progress_current = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let progress_total = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1)); // Start with 1 to avoid div by zero
                let done_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                
                // Progress reporter thread
                let progress_current_clone = progress_current.clone();
                let progress_total_clone = progress_total.clone();
                let done_flag_clone = done_flag.clone();
                let app_for_timer = app_for_hash.clone();
                let path_for_timer = path_for_hash.clone();
                let progress_thread = std::thread::spawn(move || {
                    let mut last_percent = 0u32;
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        if done_flag_clone.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }
                        let current = progress_current_clone.load(std::sync::atomic::Ordering::Relaxed);
                        let total = progress_total_clone.load(std::sync::atomic::Ordering::Relaxed);
                        if total > 1 {
                            let percent = ((current as f64 / total as f64) * 100.0) as u32;
                            if percent != last_percent {
                                let _ = app_for_timer.emit("batch-progress", BatchProgress {
                                    path: path_for_timer.clone(),
                                    status: "progress".to_string(),
                                    percent: percent as f64,
                                    files_completed: idx,
                                    files_total: num_files,
                                    hash: None,
                                    algorithm: None,
                                    error: None,
                                });
                                last_percent = percent;
                            }
                        }
                    }
                });
                
                // Hash based on container type
                let result = if container_for_hash.contains("e01") || container_for_hash.contains("encase") || container_for_hash.contains("ex01") {
                    ewf::verify_with_progress(&path_for_hash, &algo_for_hash, |current: usize, total: usize| {
                        progress_total.store(total, std::sync::atomic::Ordering::Relaxed);
                        progress_current.store(current, std::sync::atomic::Ordering::Relaxed);
                    })
                } else if container_for_hash.contains("raw") || container_for_hash.contains("dd") {
                    raw::verify_with_progress(&path_for_hash, &algo_for_hash, |current: u64, total: u64| {
                        progress_total.store(total as usize, std::sync::atomic::Ordering::Relaxed);
                        progress_current.store(current as usize, std::sync::atomic::Ordering::Relaxed);
                    })
                } else {
                    // AD1/L01 - use container verify
                    containers::verify(&path_for_hash, &algo_for_hash)
                        .map(|entries| {
                            entries.first()
                                .and_then(|e| e.message.clone())
                                .unwrap_or_default()
                        })
                };
                
                // Stop progress thread
                done_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = progress_thread.join();
                
                let duration = start_time.elapsed();
                let duration_ms = duration.as_millis() as u64;
                let throughput_mbs = if duration_ms > 0 && file_size > 0 {
                    Some((file_size as f64 / (1024.0 * 1024.0)) / (duration_ms as f64 / 1000.0))
                } else {
                    None
                };
                
                (result, duration_ms, throughput_mbs)
            }).await.map_err(|e| format!("Task error: {}", e))?;
            
            let (result, duration_ms, throughput_mbs) = hash_result;
            
            // Build result
            let batch_result = match result {
                Ok(hash) => {
                    debug!(idx = idx + 1, hash_prefix = %&hash[..8.min(hash.len())], "File completed");
                    let _ = app_clone.emit("batch-progress", BatchProgress {
                        path: path.clone(),
                        status: "completed".to_string(),
                        percent: 100.0,
                        files_completed: idx + 1,
                        files_total: num_files,
                        hash: Some(hash.clone()),
                        algorithm: Some(algo.to_uppercase()),
                        error: None,
                    });
                    BatchHashResult {
                        path,
                        algorithm: algo.to_uppercase(),
                        hash: Some(hash),
                        error: None,
                        duration_ms: Some(duration_ms),
                        throughput_mbs,
                    }
                }
                Err(e) => {
                    debug!(idx = idx + 1, error = %e, "File error");
                    let _ = app_clone.emit("batch-progress", BatchProgress {
                        path: path.clone(),
                        status: "error".to_string(),
                        percent: 0.0,
                        files_completed: idx + 1,
                        files_total: num_files,
                        hash: None,
                        algorithm: None,
                        error: Some(e.clone()),
                    });
                    BatchHashResult {
                        path,
                        algorithm: algo.to_uppercase(),
                        hash: None,
                        error: Some(e),
                        duration_ms: Some(duration_ms),
                        throughput_mbs: None,
                    }
                }
            };
            
            Ok::<BatchHashResult, String>(batch_result)
        });
        
        handles.push(handle);
    }
    
    // Wait for all tasks to complete and collect results
    let mut results = Vec::with_capacity(num_files);
    for handle in handles {
        match handle.await {
            Ok(Ok(result)) => results.push(result),
            Ok(Err(e)) => {
                debug!(error = %e, "Task error");
                // Error already emitted in the task
            }
            Err(e) => {
                debug!(error = %e, "Join error");
            }
        }
    }
    
    info!(num_files, results = results.len(), "Batch hash complete");
    Ok(results)
}

#[derive(Clone, serde::Deserialize)]
struct BatchFileInput {
    path: String,
    container_type: String,
}

// System Stats Command
#[derive(Clone, serde::Serialize)]
struct SystemStats {
    cpu_usage: f32,
    memory_used: u64,
    memory_total: u64,
    memory_percent: f32,
    // App-specific stats
    app_cpu_usage: f32,
    app_memory: u64,
    app_threads: usize,
    cpu_cores: usize,
}

use std::sync::{OnceLock, Mutex as StdMutex};

static SYSTEM: OnceLock<StdMutex<sysinfo::System>> = OnceLock::new();

fn get_system() -> &'static StdMutex<sysinfo::System> {
    SYSTEM.get_or_init(|| {
        let mut sys = sysinfo::System::new_all();
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        StdMutex::new(sys)
    })
}

fn collect_system_stats() -> SystemStats {
    let mut sys = get_system().lock().unwrap();
    sys.refresh_cpu_usage();
    sys.refresh_memory();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    
    let cpu_usage = sys.global_cpu_usage();
    let memory_used = sys.used_memory();
    let memory_total = sys.total_memory();
    let memory_percent = if memory_total > 0 {
        (memory_used as f32 / memory_total as f32) * 100.0
    } else {
        0.0
    };
    
    // Get app-specific stats
    let pid = sysinfo::Pid::from_u32(std::process::id());
    let (app_cpu_usage, app_memory, app_threads) = if let Some(process) = sys.process(pid) {
        (process.cpu_usage(), process.memory(), process.tasks().map(|t| t.len()).unwrap_or(1))
    } else {
        (0.0, 0, 1)
    };
    
    let cpu_cores = sys.cpus().len();
    
    SystemStats {
        cpu_usage,
        memory_used,
        memory_total,
        memory_percent,
        app_cpu_usage,
        app_memory,
        app_threads,
        cpu_cores,
    }
}

#[tauri::command]
fn get_system_stats() -> SystemStats {
    collect_system_stats()
}

/// Start background system stats monitoring - emits "system-stats" events every 2 seconds
fn start_system_stats_monitor(app_handle: tauri::AppHandle) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let stats = collect_system_stats();
            let _ = app_handle.emit("system-stats", stats);
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // Start background system stats monitoring
            start_system_stats_monitor(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            logical_info,
            logical_info_fast,
            logical_verify,
            logical_extract,
            scan_directory,
            scan_directory_recursive,
            scan_directory_streaming,
            e01_v3_info,
            e01_v3_verify,
            e01_verify_segments,
            raw_info,
            raw_verify,
            raw_verify_segments,
            batch_hash,
            get_system_stats
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
