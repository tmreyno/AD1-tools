mod ad1;
mod containers;

#[tauri::command]
fn logical_info(
    input_path: String,
    include_tree: bool,
) -> Result<containers::ContainerInfo, String> {
    containers::info(&input_path, include_tree)
}

#[tauri::command]
fn logical_verify(
    input_path: String,
    algorithm: String,
) -> Result<Vec<ad1::VerifyEntry>, String> {
    containers::verify(&input_path, &algorithm)
}

#[tauri::command]
fn logical_extract(input_path: String, output_dir: String) -> Result<(), String> {
    containers::extract(&input_path, &output_dir)
}

#[tauri::command]
fn scan_directory(dir_path: String) -> Result<Vec<containers::DiscoveredFile>, String> {
    containers::scan_directory(&dir_path)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            logical_info,
            logical_verify,
            logical_extract,
            scan_directory
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
