// L01 (Logical Evidence File) parser
// Implements reading AccessData Logical Evidence File format

use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use tracing::{debug, trace, instrument};

use crate::common::binary::{read_u8, read_u32_le, read_u64_le, read_string};

// L01 Format Constants
const L01_SIGNATURE: &[u8; 4] = b"L01\x00";

#[derive(Serialize, Clone)]
pub struct L01Info {
    pub format_version: u32,
    pub case_info: String,
    pub examiner: Option<String>,
    pub description: Option<String>,
    pub file_count: u32,
    pub total_size: u64,
}

#[derive(Serialize, Clone)]
#[allow(dead_code)]
pub struct L01TreeEntry {
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
}

#[instrument]
pub fn info(path: &str) -> Result<L01Info, String> {
    debug!("Reading L01 info");
    let mut file = open_and_validate(path)?;
    
    // Read L01 header
    let version = read_u32_le(&mut file)?;
    trace!(version, "L01 format version");
    
    // Read case information string
    let case_info_len = read_u32_le(&mut file)?;
    let case_info = read_string(&mut file, case_info_len as usize)?;
    
    // Read optional metadata
    let metadata_offset = read_u64_le(&mut file)?;
    let file_count = read_u32_le(&mut file)?;
    let total_size = read_u64_le(&mut file)?;
    
    // Read additional metadata if present
    let mut examiner = None;
    let mut description = None;
    
    if metadata_offset > 0 {
        file.seek(SeekFrom::Start(metadata_offset))
            .map_err(|e| format!("Failed to seek to metadata: {e}"))?;
        
        // Read metadata entries
        let metadata_count = read_u32_le(&mut file)?;
        trace!(metadata_count, "Reading metadata entries");
        for _ in 0..metadata_count {
            let key = read_string_with_length(&mut file)?;
            let value = read_string_with_length(&mut file)?;
            
            match key.to_lowercase().as_str() {
                "examiner" => examiner = Some(value),
                "description" => description = Some(value),
                _ => {}
            }
        }
    }
    
    debug!(file_count, total_size, "L01 info loaded");
    Ok(L01Info {
        format_version: version,
        case_info,
        examiner,
        description,
        file_count,
        total_size,
    })
}

#[allow(dead_code)]
pub fn build_tree(path: &str) -> Result<Vec<L01TreeEntry>, String> {
    let mut file = open_and_validate(path)?;
    
    // Skip header to file entries
    file.seek(SeekFrom::Start(64))
        .map_err(|e| format!("Failed to seek to file entries: {e}"))?;
    
    let entry_count = read_u32_le(&mut file)?;
    let mut entries = Vec::new();
    
    for _ in 0..entry_count {
        let path = read_string_with_length(&mut file)?;
        let is_dir = read_u8(&mut file)? != 0;
        let size = read_u64_le(&mut file)?;
        
        entries.push(L01TreeEntry {
            path,
            is_dir,
            size,
        });
    }
    
    debug!(entry_count = entries.len(), "Built L01 tree");
    Ok(entries)
}

pub fn is_l01(path: &str) -> Result<bool, String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("File not found: {path}"));
    }
    
    let mut file = File::open(path_obj)
        .map_err(|e| format!("Failed to open file: {e}"))?;
    
    let mut signature = [0u8; 4];
    file.read_exact(&mut signature)
        .map_err(|e| format!("Failed to read signature: {e}"))?;
    
    let is_l01 = &signature == L01_SIGNATURE;
    trace!(path, is_l01, "L01 signature check");
    Ok(is_l01)
}

fn open_and_validate(path: &str) -> Result<File, String> {
    trace!(path, "Opening L01 file");
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("File not found: {path}"));
    }
    
    let mut file = File::open(path_obj)
        .map_err(|e| format!("Failed to open L01 file: {e}"))?;
    
    let mut signature = [0u8; 4];
    file.read_exact(&mut signature)
        .map_err(|e| format!("Failed to read file signature: {e}"))?;
    
    if &signature != L01_SIGNATURE {
        return Err("File is not a valid L01 image".to_string());
    }
    
    Ok(file)
}



// Helper function to read length-prefixed string
fn read_string_with_length(file: &mut File) -> Result<String, String> {
    let length = read_u32_le(file)? as usize;
    read_string(file, length)
}
