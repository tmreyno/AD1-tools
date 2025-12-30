// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Initialize logging/tracing system
    // Control log level with RUST_LOG env var:
    //   RUST_LOG=debug ./ffx-check
    //   RUST_LOG=ffx_check_lib::ewf=trace ./ffx-check
    ffx_check_lib::logging::init();
    
    ffx_check_lib::run()
}
