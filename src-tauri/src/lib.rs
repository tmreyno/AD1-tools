mod ad1;
pub mod common;  // Shared utilities (hash, binary, segments)
pub mod ewf;  // Expert Witness Format (E01/EWF/Ex01) parser
mod l01;
pub mod raw;  // Raw disk images (.dd, .raw, .img, .001, etc.)
mod containers;

use tauri::Emitter;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::thread;

#[tauri::command]
fn logical_info(
    #[allow(non_snake_case)]
    inputPath: String,
    #[allow(non_snake_case)]
    includeTree: bool,
) -> Result<containers::ContainerInfo, String> {
    containers::info(&inputPath, includeTree)
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
async fn scan_directory_streaming(
    window: tauri::Window,
    #[allow(non_snake_case)]
    dirPath: String,
    recursive: bool,
) -> Result<usize, String> {
    // Run on blocking thread pool
    tauri::async_runtime::spawn_blocking(move || {
        containers::scan_directory_streaming(&dirPath, recursive, |file| {
            let _ = window.emit("scan-file-found", &file);
        })
    })
    .await
    .map_err(|e| format!("Task failed: {e}"))?
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
            let num_segments = num_segments;
            let segment_number = (idx + 1) as u32;
            
            s.spawn(move |_| {
                let segment_name = seg_path.file_name()
                    .map(|f| f.to_string_lossy().to_string())
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
            let num_segments = num_segments;
            let segment_number = (idx + 1) as u32;
            
            s.spawn(move |_| {
                let segment_name = seg_path.file_name()
                    .map(|f| f.to_string_lossy().to_string())
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
}

// Progress update for batch hashing
#[derive(Clone, serde::Serialize)]
struct BatchProgress {
    path: String,
    status: String,  // "started", "progress", "completed", "error"
    percent: f64,
    files_completed: usize,
    files_total: usize,
}

/// Hash multiple files in parallel using all available CPU cores
#[tauri::command]
async fn batch_hash(
    files: Vec<BatchFileInput>,
    algorithm: String,
    app: tauri::AppHandle,
) -> Result<Vec<BatchHashResult>, String> {
    use std::sync::Mutex;
    
    let num_files = files.len();
    if num_files == 0 {
        return Ok(Vec::new());
    }
    
    // Determine parallelism - use available cores but cap at file count
    let num_cpus = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let parallelism = num_cpus.min(num_files);
    
    // Shared state
    let files_completed = Arc::new(AtomicUsize::new(0));
    let results: Arc<Mutex<Vec<BatchHashResult>>> = Arc::new(Mutex::new(Vec::with_capacity(num_files)));
    let app = Arc::new(app);
    let algorithm = Arc::new(algorithm);
    
    // Create thread pool
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(parallelism)
        .build()
        .map_err(|e| format!("Failed to create thread pool: {}", e))?;
    
    pool.scope(|s| {
        for file in files {
            let files_completed = Arc::clone(&files_completed);
            let results = Arc::clone(&results);
            let app = Arc::clone(&app);
            let algorithm = Arc::clone(&algorithm);
            let num_files = num_files;
            
            s.spawn(move |_| {
                let path = file.path.clone();
                let container_type = file.container_type.to_lowercase();
                
                // Emit start event
                let _ = app.emit("batch-progress", BatchProgress {
                    path: path.clone(),
                    status: "started".to_string(),
                    percent: 0.0,
                    files_completed: files_completed.load(Ordering::Relaxed),
                    files_total: num_files,
                });
                
                // Hash based on container type
                let hash_result = if container_type.contains("e01") || container_type.contains("encase") || container_type.contains("ex01") {
                    ewf::verify_with_progress(&path, &algorithm, |current, total| {
                        let percent = (current as f64 / total as f64) * 100.0;
                        let _ = app.emit("batch-progress", BatchProgress {
                            path: path.clone(),
                            status: "progress".to_string(),
                            percent,
                            files_completed: files_completed.load(Ordering::Relaxed),
                            files_total: num_files,
                        });
                    })
                } else if container_type.contains("raw") || container_type.contains("dd") {
                    raw::verify_with_progress(&path, &algorithm, |current, total| {
                        let percent = (current as f64 / total as f64) * 100.0;
                        let _ = app.emit("batch-progress", BatchProgress {
                            path: path.clone(),
                            status: "progress".to_string(),
                            percent,
                            files_completed: files_completed.load(Ordering::Relaxed),
                            files_total: num_files,
                        });
                    })
                } else {
                    // AD1/L01 - use container verify
                    containers::verify(&path, &algorithm)
                        .map(|entries| {
                            entries.first()
                                .and_then(|e| e.message.clone())
                                .unwrap_or_default()
                        })
                };
                
                // Record result
                let completed = files_completed.fetch_add(1, Ordering::SeqCst) + 1;
                
                let result = match hash_result {
                    Ok(hash) => {
                        let _ = app.emit("batch-progress", BatchProgress {
                            path: path.clone(),
                            status: "completed".to_string(),
                            percent: 100.0,
                            files_completed: completed,
                            files_total: num_files,
                        });
                        BatchHashResult {
                            path,
                            algorithm: algorithm.to_uppercase(),
                            hash: Some(hash),
                            error: None,
                        }
                    }
                    Err(e) => {
                        let _ = app.emit("batch-progress", BatchProgress {
                            path: path.clone(),
                            status: "error".to_string(),
                            percent: 0.0,
                            files_completed: completed,
                            files_total: num_files,
                        });
                        BatchHashResult {
                            path,
                            algorithm: algorithm.to_uppercase(),
                            hash: None,
                            error: Some(e),
                        }
                    }
                };
                
                results.lock().unwrap().push(result);
            });
        }
    });
    
    let final_results = Arc::try_unwrap(results)
        .map_err(|_| "Failed to unwrap results")?
        .into_inner()
        .map_err(|e| format!("Lock error: {}", e))?;
    
    Ok(final_results)
}

#[derive(Clone, serde::Deserialize)]
struct BatchFileInput {
    path: String,
    container_type: String,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            logical_info,
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
            batch_hash
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
