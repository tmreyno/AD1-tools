use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::ad1;

#[derive(Serialize)]
pub struct ContainerInfo {
    pub container: String,
    pub ad1: Option<ad1::Ad1Info>,
    pub note: Option<String>,
}

#[derive(Serialize)]
pub struct DiscoveredFile {
    pub path: String,
    pub filename: String,
    pub container_type: String,
    pub size: u64,
}

enum ContainerKind {
    Ad1,
    L01,
}

pub fn info(path: &str, include_tree: bool) -> Result<ContainerInfo, String> {
    let kind = detect_container(path)?;
    match kind {
        ContainerKind::Ad1 => {
            let info = ad1::info(path, include_tree)?;
            Ok(ContainerInfo {
                container: "AD1".to_string(),
                ad1: Some(info),
                note: None,
            })
        }
        ContainerKind::L01 => Ok(ContainerInfo {
            container: "L01".to_string(),
            ad1: None,
            note: Some("L01/Lx01 support is not implemented yet.".to_string()),
        }),
    }
}

pub fn verify(path: &str, algorithm: &str) -> Result<Vec<ad1::VerifyEntry>, String> {
    match detect_container(path)? {
        ContainerKind::Ad1 => ad1::verify(path, algorithm),
        ContainerKind::L01 => Err("L01/Lx01 verification is not implemented yet.".to_string()),
    }
}

pub fn extract(path: &str, output_dir: &str) -> Result<(), String> {
    match detect_container(path)? {
        ContainerKind::Ad1 => ad1::extract(path, output_dir),
        ContainerKind::L01 => Err("L01/Lx01 extraction is not implemented yet.".to_string()),
    }
}

fn detect_container(path: &str) -> Result<ContainerKind, String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("Input file not found: {path}"));
    }

    let lower = path.to_lowercase();
    if lower.ends_with(".l01") || lower.ends_with(".lx01") {
        return Ok(ContainerKind::L01);
    }

    if ad1::is_ad1(path)? {
        return Ok(ContainerKind::Ad1);
    }

    Err("Unsupported or unrecognized logical container.".to_string())
}

pub fn scan_directory(dir_path: &str) -> Result<Vec<DiscoveredFile>, String> {
    let path = Path::new(dir_path);
    if !path.exists() {
        return Err(format!("Directory not found: {dir_path}"));
    }
    if !path.is_dir() {
        return Err(format!("Path is not a directory: {dir_path}"));
    }

    let mut discovered = Vec::new();

    let entries = fs::read_dir(path)
        .map_err(|e| format!("Failed to read directory: {e}"))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let entry_path = entry.path();
        if !entry_path.is_file() {
            continue;
        }

        let path_str = match entry_path.to_str() {
            Some(s) => s,
            None => continue,
        };

        let filename = entry
            .file_name()
            .to_string_lossy()
            .to_string();

        let lower = filename.to_lowercase();
        
        // Check for forensic container files
        let container_type = if lower.ends_with(".ad1") || lower.ends_with(".ad2") || lower.ends_with(".ad3") {
            // Verify it's actually an AD1 file
            match ad1::is_ad1(path_str) {
                Ok(true) => Some("AD1"),
                _ => None,
            }
        } else if lower.ends_with(".l01") {
            Some("L01")
        } else if lower.ends_with(".lx01") {
            Some("Lx01")
        } else if lower.ends_with(".e01") {
            Some("E01")
        } else if lower.ends_with(".ex01") {
            Some("Ex01")
        } else if lower.ends_with(".aff") || lower.ends_with(".afd") {
            Some("AFF")
        } else {
            None
        };

        if let Some(ctype) = container_type {
            let size = entry.metadata()
                .map(|m| m.len())
                .unwrap_or(0);

            discovered.push(DiscoveredFile {
                path: path_str.to_string(),
                filename,
                container_type: ctype.to_string(),
                size,
            });
        }
    }

    Ok(discovered)
}
