// L01 (Logical Evidence File) parser
// Implements reading AccessData Logical Evidence File format

use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

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

pub fn info(path: &str) -> Result<L01Info, String> {
    let mut file = open_and_validate(path)?;
    
    // Read L01 header
    let version = read_u32(&mut file)?;
    
    // Read case information string
    let case_info_len = read_u32(&mut file)?;
    let case_info = read_string(&mut file, case_info_len as usize)?;
    
    // Read optional metadata
    let metadata_offset = read_u64(&mut file)?;
    let file_count = read_u32(&mut file)?;
    let total_size = read_u64(&mut file)?;
    
    // Read additional metadata if present
    let mut examiner = None;
    let mut description = None;
    
    if metadata_offset > 0 {
        file.seek(SeekFrom::Start(metadata_offset))
            .map_err(|e| format!("Failed to seek to metadata: {e}"))?;
        
        // Read metadata entries
        let metadata_count = read_u32(&mut file)?;
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
    
    let entry_count = read_u32(&mut file)?;
    let mut entries = Vec::new();
    
    for _ in 0..entry_count {
        let path = read_string_with_length(&mut file)?;
        let is_dir = read_u8(&mut file)? != 0;
        let size = read_u64(&mut file)?;
        
        entries.push(L01TreeEntry {
            path,
            is_dir,
            size,
        });
    }
    
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
    
    Ok(&signature == L01_SIGNATURE)
}

fn open_and_validate(path: &str) -> Result<File, String> {
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

// Helper functions
#[allow(dead_code)]
fn read_u8(file: &mut File) -> Result<u8, String> {
    let mut buf = [0u8; 1];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read u8: {e}"))?;
    Ok(buf[0])
}

fn read_u32(file: &mut File) -> Result<u32, String> {
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read u32: {e}"))?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64(file: &mut File) -> Result<u64, String> {
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read u64: {e}"))?;
    Ok(u64::from_le_bytes(buf))
}

fn read_string(file: &mut File, length: usize) -> Result<String, String> {
    let mut buf = vec![0u8; length];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read string: {e}"))?;
    
    // Find null terminator
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..end]).to_string())
}

fn read_string_with_length(file: &mut File) -> Result<String, String> {
    let length = read_u32(file)? as usize;
    read_string(file, length)
}
