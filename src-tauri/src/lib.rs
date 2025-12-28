mod ad1;
pub mod ewf;  // Expert Witness Format (E01/EWF/Ex01) parser
mod l01;
pub mod raw;  // Raw disk images (.dd, .raw, .img, .001, etc.)
mod containers;

use tauri::Emitter;

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
            e01_v3_info,
            e01_v3_verify,
            raw_info,
            raw_verify
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
