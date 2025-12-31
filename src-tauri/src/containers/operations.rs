//! Core container operations (info, verify, extract)
//!
//! This module provides the main entry points for working with forensic containers.

use tracing::debug;
use std::path::Path;

use crate::ad1;
use crate::archive;
use crate::ewf;
use crate::l01;
use crate::raw;
use crate::ufed;

use super::types::{ContainerInfo, ContainerKind, VerifyEntry};
use super::companion::find_companion_log;

/// Fast info - only reads headers, doesn't parse full item trees
/// Use this for quick container listing/display
pub fn info_fast(path: &str) -> Result<ContainerInfo, String> {
    debug!("info_fast: loading {}", path);
    let kind = detect_container(path).map_err(|e| {
        debug!("info_fast: detect_container failed for {}: {}", path, e);
        e
    })?;
    let companion_log = find_companion_log(path);
    
    match kind {
        ContainerKind::Ad1 => {
            let info = ad1::info_fast(path)?;
            Ok(ContainerInfo {
                container: "AD1".to_string(),
                ad1: Some(info),
                e01: None,
                l01: None,
                raw: None,
                archive: None,
                ufed: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::E01 => {
            let info = ewf::info(path)?;
            Ok(ContainerInfo {
                container: "E01".to_string(),
                ad1: None,
                e01: Some(info),
                l01: None,
                raw: None,
                archive: None,
                ufed: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::L01 => {
            let info = l01::info(path)?;
            Ok(ContainerInfo {
                container: "L01".to_string(),
                ad1: None,
                e01: None,
                l01: Some(info),
                raw: None,
                archive: None,
                ufed: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::Raw => {
            let info = raw::info(path)?;
            Ok(ContainerInfo {
                container: "RAW".to_string(),
                ad1: None,
                e01: None,
                l01: None,
                raw: Some(info),
                archive: None,
                ufed: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::Archive => {
            let info = archive::info(path)?;
            Ok(ContainerInfo {
                container: format!("Archive ({})", info.format),
                ad1: None,
                e01: None,
                l01: None,
                raw: None,
                archive: Some(info),
                ufed: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::Ufed => {
            let info = ufed::info(path)?;
            Ok(ContainerInfo {
                container: format!("UFED ({})", info.format),
                ad1: None,
                e01: None,
                l01: None,
                raw: None,
                archive: None,
                ufed: Some(info),
                note: None,
                companion_log,
            })
        }
    }
}

/// Full info - reads headers and optionally parses item trees
pub fn info(path: &str, include_tree: bool) -> Result<ContainerInfo, String> {
    let kind = detect_container(path)?;
    let companion_log = find_companion_log(path);
    
    match kind {
        ContainerKind::Ad1 => {
            let info = ad1::info(path, include_tree)?;
            Ok(ContainerInfo {
                container: "AD1".to_string(),
                ad1: Some(info),
                e01: None,
                l01: None,
                raw: None,
                archive: None,
                ufed: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::E01 => {
            let info = ewf::info(path)?;
            Ok(ContainerInfo {
                container: "E01".to_string(),
                ad1: None,
                e01: Some(info),
                l01: None,
                raw: None,
                archive: None,
                ufed: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::L01 => {
            let info = l01::info(path)?;
            Ok(ContainerInfo {
                container: "L01".to_string(),
                ad1: None,
                e01: None,
                l01: Some(info),
                raw: None,
                archive: None,
                ufed: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::Raw => {
            let info = raw::info(path)?;
            Ok(ContainerInfo {
                container: "RAW".to_string(),
                ad1: None,
                e01: None,
                l01: None,
                raw: Some(info),
                archive: None,
                ufed: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::Archive => {
            let info = archive::info(path)?;
            Ok(ContainerInfo {
                container: format!("Archive ({})", info.format),
                ad1: None,
                e01: None,
                l01: None,
                raw: None,
                archive: Some(info),
                ufed: None,
                note: None,
                companion_log,
            })
        }
        ContainerKind::Ufed => {
            let info = ufed::info(path)?;
            Ok(ContainerInfo {
                container: format!("UFED ({})", info.format),
                ad1: None,
                e01: None,
                l01: None,
                raw: None,
                archive: None,
                ufed: Some(info),
                note: None,
                companion_log,
            })
        }
    }
}

/// Verify container integrity using the specified hash algorithm
pub fn verify(path: &str, algorithm: &str) -> Result<Vec<VerifyEntry>, String> {
    match detect_container(path)? {
        ContainerKind::Ad1 => {
            let ad1_results = ad1::verify(path, algorithm)?;
            Ok(ad1_results.into_iter().map(|entry| VerifyEntry {
                path: Some(entry.path),
                chunk_index: None,
                status: entry.status,
                message: None,
            }).collect())
        }
        ContainerKind::E01 => {
            let ewf_results = ewf::verify_chunks(path, algorithm)?;
            Ok(ewf_results.into_iter().map(|entry| VerifyEntry {
                path: None,
                chunk_index: Some(entry.chunk_index),
                status: entry.status,
                message: entry.message,
            }).collect())
        }
        ContainerKind::L01 => Err("L01 verification is not implemented yet.".to_string()),
        ContainerKind::Raw => {
            let computed_hash = raw::verify(path, algorithm)?;
            Ok(vec![VerifyEntry {
                path: None,
                chunk_index: None,
                status: "computed".to_string(),
                message: Some(format!("{}: {}", algorithm.to_uppercase(), computed_hash)),
            }])
        }
        ContainerKind::Archive => Err("Archive verification is not implemented yet. Use standard archive tools.".to_string()),
        ContainerKind::Ufed => Err("UFED verification is not implemented yet.".to_string()),
    }
}

/// Extract container contents to the specified output directory
pub fn extract(path: &str, output_dir: &str) -> Result<(), String> {
    match detect_container(path)? {
        ContainerKind::Ad1 => ad1::extract(path, output_dir),
        ContainerKind::E01 => ewf::extract(path, output_dir),
        ContainerKind::L01 => Err("L01 extraction is not implemented yet.".to_string()),
        ContainerKind::Raw => raw::extract(path, output_dir),
        ContainerKind::Archive => Err("Archive extraction is not implemented yet. Use standard archive tools (7z, unzip).".to_string()),
        ContainerKind::Ufed => Err("UFED extraction is not implemented yet. The UFED container is typically already extracted.".to_string()),
    }
}

/// Detect the container type from the file path and magic bytes
pub(crate) fn detect_container(path: &str) -> Result<ContainerKind, String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("Input file not found: {path}"));
    }

    let lower = path.to_lowercase();
    
    // Check Cellebrite UFED formats first (UFD, UFDR, UFDX)
    if ufed::is_ufed(path) {
        return Ok(ContainerKind::Ufed);
    }
    
    // Check E01/EWF first (before L01 to avoid .lx01 confusion)
    // Support .e01, .ex01, .e02, .e03, etc., and .ewf extensions
    if lower.ends_with(".e01") || lower.ends_with(".ex01") || lower.ends_with(".ewf") 
        || lower.contains(".e0") || lower.contains(".ex")
    {
        debug!("Checking E01 signature for: {}", path);
        if ewf::is_e01(path).unwrap_or(false) {
            return Ok(ContainerKind::E01);
        } else {
            debug!("E01 signature check failed for: {}", path);
        }
    }
    
    // Check L01
    if (lower.ends_with(".l01") || lower.ends_with(".lx01"))
        && l01::is_l01(path).unwrap_or(false) 
    {
        return Ok(ContainerKind::L01);
    }

    // Check AD1
    if ad1::is_ad1(path)? {
        return Ok(ContainerKind::Ad1);
    }

    // Check archive formats (7z, ZIP, RAR, etc.) - before raw to catch .7z.001 properly
    if archive::is_archive(path).unwrap_or(false) {
        return Ok(ContainerKind::Archive);
    }

    // Check raw disk images (.dd, .raw, .img, .001, .002, etc.)
    if raw::is_raw(path).unwrap_or(false) {
        return Ok(ContainerKind::Raw);
    }

    Err(format!("Unsupported or unrecognized logical container: {}\nSupported formats: AD1, E01/EWF, L01, RAW (.dd, .raw, .img, .001), Archives (7z, ZIP, RAR), UFED (UFD, UFDR, UFDX)", path))
}
