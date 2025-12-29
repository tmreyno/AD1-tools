// E01 (Expert Witness Format) parser
// Implements reading and extracting EnCase EWF format images

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use flate2::read::ZlibDecoder;
use crc32fast::Hasher as Crc32;
use sha1::Digest as Sha1Digest;

// EWF Format Constants
const EWF_SIGNATURE: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";
const EWF2_SIGNATURE: &[u8; 8] = b"EVF2\x0d\x0a\x81\x00";
#[allow(dead_code)]
const SECTOR_SIZE: u64 = 512;

#[derive(Serialize, Clone)]
pub struct StoredImageHash {
    pub algorithm: String,
    pub hash: String,
}

#[derive(Serialize, Clone)]
pub struct E01Info {
    pub format_version: String,
    pub segment_count: u32,
    pub sector_count: u64,
    pub bytes_per_sector: u32,
    pub chunk_count: u32,
    pub sectors_per_chunk: u32,
    pub total_size: u64,
    pub compression: String,
    pub case_number: Option<String>,
    pub description: Option<String>,
    pub examiner_name: Option<String>,
    pub evidence_number: Option<String>,
    pub notes: Option<String>,
    pub acquiry_date: Option<String>,
    pub system_date: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub stored_hashes: Vec<StoredImageHash>,
}

#[derive(Clone)]
struct FileHeader {
    signature: [u8; 8],
    #[allow(dead_code)]
    fields_start: u8,
    #[allow(dead_code)]
    segment_number: u16,
    #[allow(dead_code)]
    fields_end: u16,
}

#[derive(Clone)]
struct SectionDescriptor {
    section_type: [u8; 16],
    next_offset: u64,
    size: u64,
}

#[derive(Clone)]
struct VolumeSection {
    #[allow(dead_code)]
    media_type: u8,
    chunk_count: u32,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    sector_count: u64,
    #[allow(dead_code)]
    chs_cylinders: u32,
    #[allow(dead_code)]
    chs_heads: u32,
    #[allow(dead_code)]
    chs_sectors: u32,
    #[allow(dead_code)]
    error_granularity: u32,
    compression_level: u8,
    #[allow(dead_code)]
    set_identifier: [u8; 16],
}

pub fn info(path: &str) -> Result<E01Info, String> {
    let mut file = open_and_validate(path)?;
    
    let header = read_file_header(&mut file)?;
    let format_version = if &header.signature == EWF2_SIGNATURE {
        "EWF2".to_string()
    } else {
        "EWF1".to_string()
    };
    
    // Read sections to find volume, header, and hash info
    let mut volume_info: Option<VolumeSection> = None;
    let mut header_strings: HashMap<String, String> = HashMap::new();
    let mut stored_hashes: Vec<StoredImageHash> = Vec::new();
    let mut current_offset = 13u64; // After file header
    let mut visited_offsets = HashSet::new();
    let mut section_count = 0u32;
    const MAX_SECTIONS: u32 = 1000; // Reasonable limit to prevent infinite loops
    
    loop {
        // Prevent infinite loops
        if section_count >= MAX_SECTIONS {
            break;
        }
        if !visited_offsets.insert(current_offset) {
            // Circular reference detected, break silently
            break;
        }
        section_count += 1;
        
        match read_section_descriptor(&mut file, current_offset) {
            Ok(section) => {
                let section_type_str = String::from_utf8_lossy(&section.section_type).trim_matches('\0').to_string();
                
                match section_type_str.as_str() {
                    "volume" | "disk" => {
                        volume_info = Some(read_volume_section(&mut file, current_offset + 24)?);
                    }
                    "header" | "header2" => {
                        header_strings.extend(read_header_section(&mut file, current_offset + 24, section.size)?);
                    }
                    "hash" => {
                        // Read hash section - contains MD5 stored in EWF format
                        if let Ok(hashes) = read_hash_section(&mut file, current_offset + 76, section.size) {
                            stored_hashes.extend(hashes);
                        }
                    }
                    "digest" => {
                        // EWF2 format uses digest section for hashes (MD5 + SHA1)
                        if let Ok(hashes) = read_digest_section(&mut file, current_offset + 76, section.size) {
                            stored_hashes.extend(hashes);
                        }
                    }
                    "done" => {
                        break;
                    }
                    _ => {}
                }
                
                if section.next_offset == 0 {
                    break;
                }
                current_offset = section.next_offset;
            }
            Err(_) => {
                break;
            }
        }
    }
    
    if volume_info.is_none() {
        return Err(format!("No volume section found in E01 file. This may not be a valid EWF format file, or it may be using an unsupported variant."));
    }
    
    let volume = volume_info.unwrap();
    
    // Determine compression
    let compression = match volume.compression_level {
        0 => "None".to_string(),
        1 => "Good (Fast)".to_string(),
        2 => "Best".to_string(),
        _ => format!("Unknown ({})", volume.compression_level),
    };
    
    // Count segments
    let segment_count = count_segments(path)?;
    let total_size = volume.sector_count * volume.bytes_per_sector as u64;
    
    Ok(E01Info {
        format_version,
        segment_count,
        sector_count: volume.sector_count,
        bytes_per_sector: volume.bytes_per_sector,
        chunk_count: volume.chunk_count,
        sectors_per_chunk: volume.sectors_per_chunk,
        total_size,
        compression,
        case_number: header_strings.get("case_number").cloned(),
        description: header_strings.get("description").cloned(),
        examiner_name: header_strings.get("examiner_name").cloned(),
        evidence_number: header_strings.get("evidence_number").cloned(),
        notes: header_strings.get("notes").cloned(),
        acquiry_date: header_strings.get("acquiry_date").cloned(),
        system_date: header_strings.get("system_date").cloned(),
        model: header_strings.get("model").cloned(),
        serial_number: header_strings.get("serial_number").cloned(),
        stored_hashes,
    })
}

pub fn is_e01(path: &str) -> Result<bool, String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("File not found: {path}"));
    }
    
    let mut file = File::open(path_obj)
        .map_err(|e| format!("Failed to open file: {e}"))?;
    
    let mut signature = [0u8; 8];
    file.read_exact(&mut signature)
        .map_err(|e| format!("Failed to read signature: {e}"))?;
    
    Ok(&signature == EWF_SIGNATURE || &signature == EWF2_SIGNATURE)
}

fn open_and_validate(path: &str) -> Result<File, String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("File not found: {path}"));
    }
    
    let mut file = File::open(path_obj)
        .map_err(|e| format!("Failed to open E01 file: {e}"))?;
    
    let mut signature = [0u8; 8];
    file.read_exact(&mut signature)
        .map_err(|e| format!("Failed to read file signature: {e}"))?;
    
    if &signature != EWF_SIGNATURE && &signature != EWF2_SIGNATURE {
        return Err("File is not a valid E01/EWF image".to_string());
    }
    
    Ok(file)
}

fn read_file_header(file: &mut File) -> Result<FileHeader, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Failed to seek: {e}"))?;
    
    let mut signature = [0u8; 8];
    file.read_exact(&mut signature)
        .map_err(|e| format!("Failed to read signature: {e}"))?;
    
    let mut buf = [0u8; 5];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read header: {e}"))?;
    
    Ok(FileHeader {
        signature,
        fields_start: buf[0],
        segment_number: u16::from_le_bytes([buf[1], buf[2]]),
        fields_end: u16::from_le_bytes([buf[3], buf[4]]),
    })
}

fn read_section_descriptor(file: &mut File, offset: u64) -> Result<SectionDescriptor, String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek to section: {e}"))?;
    
    let mut section_type = [0u8; 16];
    file.read_exact(&mut section_type)
        .map_err(|e| format!("Failed to read section type: {e}"))?;
    
    let next_offset = read_u64(file)?;
    let size = read_u64(file)?;
    
    Ok(SectionDescriptor {
        section_type,
        next_offset,
        size,
    })
}

fn read_volume_section(file: &mut File, offset: u64) -> Result<VolumeSection, String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek to volume section: {e}"))?;
    
    // Read first 64 bytes to determine format
    let mut debug_buf = vec![0u8; 64];
    file.read_exact(&mut debug_buf)
        .map_err(|e| format!("Failed to read section header: {e}"))?;
    
    // Check if this is the alternative "disk" format (many zeros at start)
    let is_disk_format = debug_buf[4..48].iter().all(|&b| b == 0);
    
    // Reset to start of section
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek to volume section: {e}"))?;
    
    if is_disk_format {
        // Disk format: skip 48 bytes of header/zeros
        file.seek(SeekFrom::Current(48))
            .map_err(|e| format!("Failed to skip disk header: {e}"))?;
        
        // Skip 4 bytes (unknown identifier)
        file.seek(SeekFrom::Current(4))
            .map_err(|e| format!("Failed to skip identifier: {e}"))?;
        
        let media_type = read_u8(file)?;
        file.seek(SeekFrom::Current(3))
            .map_err(|e| format!("Failed to skip padding: {e}"))?; // padding
        
        let sector_count = read_u32(file)? as u64;
        let sectors_per_chunk = read_u32(file)?;
        let bytes_per_sector = read_u32(file)?;
        
        let chunk_count = if sectors_per_chunk > 0 {
            ((sector_count + sectors_per_chunk as u64 - 1) / sectors_per_chunk as u64) as u32
        } else {
            0
        };
        
        Ok(VolumeSection {
            chunk_count,
            sectors_per_chunk,
            bytes_per_sector,
            sector_count,
            chs_cylinders: 0,
            chs_heads: 0,
            chs_sectors: 0,
            media_type,
            error_granularity: 0,
            compression_level: 1, // Assume "Good" compression
            set_identifier: [0u8; 16],
        })
    } else {
        // Standard volume format
        // Skip padding/reserved bytes
        file.seek(SeekFrom::Current(4))
            .map_err(|e| format!("Failed to skip padding: {e}"))?;
        
        let chunk_count = read_u32(file)?;
        let sectors_per_chunk = read_u32(file)?;
        let bytes_per_sector = read_u32(file)?;
        let sector_count = read_u64(file)?;
        
        let chs_cylinders = read_u32(file)?;
        let chs_heads = read_u32(file)?;
        let chs_sectors = read_u32(file)?;
        
        let media_type = read_u8(file)?;
    
        // Skip reserved bytes
        file.seek(SeekFrom::Current(3))
            .map_err(|e| format!("Failed to skip reserved: {e}"))?;
        
        let error_granularity = read_u32(file)?;
        
        // Skip more reserved
        file.seek(SeekFrom::Current(4))
            .map_err(|e| format!("Failed to skip reserved: {e}"))?;
        
        let mut set_identifier = [0u8; 16];
        file.read_exact(&mut set_identifier)
            .map_err(|e| format!("Failed to read set identifier: {e}"))?;
        
        // Skip to compression level (offset varies, approximate)
        let compression_level = 1u8; // Default assumption
        
        Ok(VolumeSection {
            media_type,
            chunk_count,
            sectors_per_chunk,
            bytes_per_sector,
            sector_count,
            chs_cylinders,
            chs_heads,
            chs_sectors,
            error_granularity,
            compression_level,
            set_identifier,
        })
    }
}

fn read_header_section(
    file: &mut File,
    offset: u64,
    size: u64,
) -> Result<std::collections::HashMap<String, String>, String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek to header section: {e}"))?;
    
    let mut data = vec![0u8; size as usize];
    file.read_exact(&mut data)
        .map_err(|e| format!("Failed to read header data: {e}"))?;
    
    let mut result = std::collections::HashMap::new();
    
    // Parse UTF-16LE null-terminated strings
    // Format: key\0value\0key\0value\0
    let text = String::from_utf8_lossy(&data);
    let parts: Vec<&str> = text.split('\0').filter(|s| !s.is_empty()).collect();
    
    let mut i = 0;
    while i + 1 < parts.len() {
        let key = parts[i].trim().to_lowercase().replace(' ', "_");
        let value = parts[i + 1].trim().to_string();
        if !value.is_empty() {
            result.insert(key, value);
        }
        i += 2;
    }
    
    Ok(result)
}

/// Read hash section from EWF file (contains MD5 hash)
/// Hash section structure:
/// - 16 bytes: MD5 hash
/// - 16 bytes: unknown/reserved (sometimes contains additional data)
/// - 4 bytes: checksum
fn read_hash_section(
    file: &mut File,
    offset: u64,
    _size: u64,
) -> Result<Vec<StoredImageHash>, String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek to hash section: {e}"))?;
    
    let mut hashes = Vec::new();
    
    // Read MD5 hash (16 bytes)
    let mut md5_bytes = [0u8; 16];
    if file.read_exact(&mut md5_bytes).is_ok() {
        // Check if it's not all zeros (valid hash)
        if md5_bytes.iter().any(|&b| b != 0) {
            let md5_hash = md5_bytes.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            hashes.push(StoredImageHash {
                algorithm: "MD5".to_string(),
                hash: md5_hash,
            });
        }
    }
    
    Ok(hashes)
}

/// Read digest section from EWF2 format (contains both MD5 and SHA1)
/// Digest section structure:
/// - 16 bytes: MD5 hash
/// - 20 bytes: SHA1 hash
/// - padding/checksum
fn read_digest_section(
    file: &mut File,
    offset: u64,
    size: u64,
) -> Result<Vec<StoredImageHash>, String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek to digest section: {e}"))?;
    
    let mut hashes = Vec::new();
    
    // Read MD5 hash (16 bytes)
    let mut md5_bytes = [0u8; 16];
    if file.read_exact(&mut md5_bytes).is_ok() {
        if md5_bytes.iter().any(|&b| b != 0) {
            let md5_hash = md5_bytes.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            hashes.push(StoredImageHash {
                algorithm: "MD5".to_string(),
                hash: md5_hash,
            });
        }
    }
    
    // Read SHA1 hash (20 bytes) if section is large enough
    if size >= 36 {
        let mut sha1_bytes = [0u8; 20];
        if file.read_exact(&mut sha1_bytes).is_ok() {
            if sha1_bytes.iter().any(|&b| b != 0) {
                let sha1_hash = sha1_bytes.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                hashes.push(StoredImageHash {
                    algorithm: "SHA1".to_string(),
                    hash: sha1_hash,
                });
            }
        }
    }
    
    Ok(hashes)
}

fn count_segments(base_path: &str) -> Result<u32, String> {
    let path = Path::new(base_path);
    let parent = path.parent().ok_or("Invalid path")?;
    let stem = path.file_stem().ok_or("No filename")?.to_string_lossy();
    
    let mut count = 1u32;
    
    // Try E01, E02, E03... pattern (check up to E99 for reasonable limit)
    for i in 2..=99 {
        let segment_name = format!("{}.E{:02}", stem, i);
        let segment_path = parent.join(&segment_name);
        if segment_path.exists() {
            count += 1;
        } else {
            // Stop at first missing segment
            break;
        }
    }
    
    // If we hit 99, check for Ex01, Ex02... pattern for larger segment numbers
    if count >= 99 {
        for i in 100..=999 {
            let segment_name = format!("{}.Ex{:02}", stem, i - 99);
            let segment_path = parent.join(&segment_name);
            if segment_path.exists() {
                count += 1;
            } else {
                break;
            }
        }
    }
    
    Ok(count)
}

// Helper functions
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

// ==============================================================================
// E01 EXTRACTION IMPLEMENTATION
// ==============================================================================

#[derive(Serialize, Clone)]
pub struct E01VerifyEntry {
    pub chunk_index: usize,
    pub status: String,
    pub message: Option<String>,
}

pub fn verify(path: &str, algorithm: &str) -> Result<Vec<E01VerifyEntry>, String> {
    eprintln!("E01::verify - Starting verification of: {}", path);
    eprintln!("E01::verify - Algorithm: {}", algorithm);
    
    let mut session = E01Session::open(path)?;
    let mut results = Vec::new();

    let total_chunks = session.table_sections.iter().map(|t| t.chunk_count).sum::<u32>();
    eprintln!("E01::verify - Total chunks to verify: {}", total_chunks);
    eprintln!("E01::verify - Number of table sections: {}", session.table_sections.len());
    eprintln!("E01::verify - Number of segment files: {}", session.files.len());

    match algorithm.to_lowercase().as_str() {
        "md5" | "sha1" => {
            // Verify by computing hash of entire extracted image
            let mut md5_hasher = md5::Context::new();
            let mut sha1_hasher = sha1::Sha1::new();
            let use_md5 = algorithm.to_lowercase() == "md5";

            for chunk_index in 0..total_chunks as usize {
                // Skip debug output except for errors
                match session.read_chunk(chunk_index) {
                    Ok(chunk_data) => {
                        if use_md5 {
                            md5_hasher.consume(&chunk_data);
                        } else {
                            sha1_hasher.update(&chunk_data);
                        }
                        
                        results.push(E01VerifyEntry {
                            chunk_index,
                            status: "ok".to_string(),
                            message: None,
                        });
                    }
                    Err(e) => {
                        // Only print first 50 errors and last 50 errors to avoid spam
                        if chunk_index < 50 || chunk_index >= (total_chunks as usize - 50) {
                            eprintln!("E01 verify: Chunk {} failed: {}", chunk_index, e);
                        }
                        results.push(E01VerifyEntry {
                            chunk_index,
                            status: "error".to_string(),
                            message: Some(format!("Failed to read chunk: {}", e)),
                        });
                    }
                }
            }

            // Print summary statistics
            let success_count = results.iter().filter(|r| r.status == "ok").count();
            let fail_count = results.iter().filter(|r| r.status == "error").count();
            eprintln!("\n========== VERIFICATION SUMMARY ==========");
            eprintln!("Total chunks: {}", total_chunks);
            eprintln!("Successful: {} ({:.2}%)", success_count, (success_count as f64 / total_chunks as f64) * 100.0);
            eprintln!("Failed: {} ({:.2}%)", fail_count, (fail_count as f64 / total_chunks as f64) * 100.0);
            eprintln!("==========================================\n");

            // Compute final hash
            let hash_str = if use_md5 {
                format!("{:x}", md5_hasher.compute())
            } else {
                format!("{:x}", sha1_hasher.finalize())
            };

            println!("E01 {} hash: {}", algorithm.to_uppercase(), hash_str);
        }
        "crc" | "crc32" => {
            // Verify CRC32 for each chunk
            for chunk_index in 0..total_chunks as usize {
                match session.read_chunk(chunk_index) {
                    Ok(chunk_data) => {
                        let mut hasher = Crc32::new();
                        hasher.update(&chunk_data);
                        let crc = hasher.finalize();
                        
                        results.push(E01VerifyEntry {
                            chunk_index,
                            status: "ok".to_string(),
                            message: Some(format!("CRC32: {:08x}", crc)),
                        });
                    }
                    Err(e) => {
                        eprintln!("E01 verify: Chunk {} failed: {}", chunk_index, e);
                        results.push(E01VerifyEntry {
                            chunk_index,
                            status: "error".to_string(),
                            message: Some(format!("Failed to read chunk: {}", e)),
                        });
                    }
                }
            }
        }
        _ => {
            return Err(format!("Unsupported algorithm: {}", algorithm));
        }
    }

    Ok(results)
}

#[derive(Clone)]
struct TableSection {
    chunk_count: u32,
    base_offset: u64,
    #[allow(dead_code)]
    checksum: u32,
    offsets: Vec<u64>,
    sectors_start: u64, // Where the 'sectors' (data) section starts
    segment_index: usize, // Which segment file this table belongs to
}

struct E01Session {
    files: Vec<File>,
    volume: VolumeSection,
    table_sections: Vec<TableSection>,
    segment_sizes: Vec<u64>,  // Actual size of each segment file
}

pub fn extract(path: &str, output_dir: &str) -> Result<(), String> {
    if output_dir.trim().is_empty() {
        return Err("Output directory is required".to_string());
    }

    // Create output directory
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create output directory: {e}"))?;

    // Open E01 session
    let mut session = E01Session::open(path)?;

    // Extract as raw image
    let output_path = Path::new(output_dir).join("extracted.dd");
    let mut output_file = File::create(&output_path)
        .map_err(|e| format!("Failed to create output file: {e}"))?;

    // Read and decompress all sectors
    let total_sectors = session.volume.sector_count;
    let sectors_per_chunk = session.volume.sectors_per_chunk as u64;
    let bytes_per_sector = session.volume.bytes_per_sector as u64;

    for sector_index in 0..total_sectors {
        let chunk_index = (sector_index / sectors_per_chunk) as usize;
        let sector_in_chunk = sector_index % sectors_per_chunk;

        // Read chunk data if it's the first sector in the chunk
        if sector_in_chunk == 0 {
            match session.read_chunk(chunk_index) {
                Ok(chunk_data) => {
                    // Write the entire chunk
                    output_file.write_all(&chunk_data)
                        .map_err(|e| format!("Failed to write chunk data: {e}"))?;
                }
                Err(e) => {
                    // Write zeros for missing/corrupt chunks
                    eprintln!("Warning: Failed to read chunk {}: {}", chunk_index, e);
                    let zeros = vec![0u8; (sectors_per_chunk * bytes_per_sector) as usize];
                    output_file.write_all(&zeros)
                        .map_err(|e| format!("Failed to write zero chunk: {e}"))?;
                }
            }
        }
    }

    Ok(())
}

impl E01Session {
    fn open(path: &str) -> Result<Self, String> {
        println!("\n########## SEGMENT-AWARE CODE v2.0 ##########");
        println!("E01::open - Opening: {}", path);
        
        let first_file = open_and_validate(path)?;

        // Open all segment files first
        let segment_count = count_segments(path)?;
        println!("E01::open - Segment count: {}", segment_count);
        
        let path_obj = Path::new(path);
        let parent = path_obj.parent().ok_or("Invalid path")?;
        let stem = path_obj.file_stem().ok_or("No filename")?.to_string_lossy();

        let mut files = vec![first_file];
        for i in 2..=segment_count {
            let segment_name = format!("{}.E{:02}", stem, i);
            let segment_path = parent.join(&segment_name);
            let segment_file = File::open(&segment_path)
                .map_err(|e| format!("Failed to open segment {}: {e}", i))?;
            files.push(segment_file);
        }

        // Collect actual sizes of all segment files
        let mut segment_sizes = Vec::new();
        for (i, file) in files.iter().enumerate() {
            let size = file.metadata()
                .map_err(|e| format!("Failed to get metadata for segment {}: {e}", i))?
                .len();
            segment_sizes.push(size);
        }

        eprintln!("E01::open - Found {} segments with sizes: {:?}", files.len(), segment_sizes);
        
        // For compatibility with section walking, use first segment size
        let segment_size = segment_sizes[0];

        // Now parse sections across all segments
        let mut current_offset = 13u64;
        let mut volume_info: Option<VolumeSection> = None;
        let mut table_sections = Vec::new();
        let mut sectors_offset: Option<u64> = None; // Track the MOST RECENT 'sectors' section
        let mut all_sectors_offsets = Vec::new(); // Track ALL sectors sections found

        loop {
            // Determine which segment and offset within segment
            let segment_index = (current_offset / segment_size) as usize;
            let offset_in_segment = current_offset % segment_size;

            if segment_index >= files.len() {
                eprintln!("E01::open - Offset {} beyond available segments", current_offset);
                break;
            }

            match read_section_descriptor(&mut files[segment_index], offset_in_segment) {
                Ok(section) => {
                    let section_type_str = String::from_utf8_lossy(&section.section_type)
                        .trim_matches('\0')
                        .to_string();

                    eprintln!("E01::open - Found section '{}' at offset {} (segment {}, offset {})", 
                             section_type_str, current_offset, segment_index, offset_in_segment);

                    match section_type_str.as_str() {
                        "volume" | "disk" => {
                            let data_offset = current_offset + 24;
                            let data_segment_index = (data_offset / segment_size) as usize;
                            let data_offset_in_segment = data_offset % segment_size;
                            
                            if data_segment_index < files.len() {
                                volume_info = Some(read_volume_section(&mut files[data_segment_index], data_offset_in_segment)?);
                            }
                        }
                        "sectors" => {
                            // Track ALL 'sectors' sections - each one contains chunk data
                            let data_start = current_offset + 24; // Skip section descriptor
                            sectors_offset = Some(data_start); // Update to most recent
                            all_sectors_offsets.push(data_start);
                            eprintln!("E01::open - Sectors section #{} starts at offset {}", 
                                     all_sectors_offsets.len(), data_start);
                        }
                        "table" => {
                            // Parse ALL table sections - each references the most recent sectors section
                            eprintln!("E01::open - Table section.size = {}", section.size);
                            let data_offset = current_offset + 24;
                            let data_segment_index = (data_offset / segment_size) as usize;
                            let data_offset_in_segment = data_offset % segment_size;
                            
                            if data_segment_index < files.len() {
                                // Use the most recent sectors section found before this table
                                let sectors_base = sectors_offset.unwrap_or(1876); // Default if not found yet
                                if let Ok(mut table) = read_table_section(&mut files[data_segment_index], data_offset_in_segment, section.size) {
                                    table.sectors_start = sectors_base;
                                    table.segment_index = data_segment_index;
                                    eprintln!("E01::open - Parsed table {} with {} chunks, base_offset={}, sectors_start={}, segment={}", 
                                             table_sections.len(), table.chunk_count, table.base_offset, table.sectors_start, data_segment_index);
                                    table_sections.push(table);
                                }
                            }
                        }
                        "done" => {
                            eprintln!("E01::open - Reached 'done' section");
                            break;
                        }
                        _ => {
                            // Unhandled section type - just skip it
                        }
                    }

                    // Check for end of chain
                    if section.next_offset == 0 {
                        eprintln!("E01::open - Section has next_offset=0, stopping");
                        break;
                    }
                    
                    // CRITICAL: Detect circular reference (section pointing to itself)
                    if section.next_offset == current_offset {
                        eprintln!("E01::open - Circular reference detected: section at {} points to itself, stopping", current_offset);
                        break;
                    }
                    
                    // Always update current_offset to move to next section
                    current_offset = section.next_offset;
                }
                Err(e) => {
                    eprintln!("E01::open - Failed to read section at offset {}: {}", current_offset, e);
                    break;
                }
            }
        }

        let volume = volume_info.ok_or("No volume section found in E01 file")?;

        eprintln!("E01::open - Parsed {} table sections", table_sections.len());
        eprintln!("E01::open - Total chunks across all tables: {}", 
                 table_sections.iter().map(|t| t.chunk_count as usize).sum::<usize>());
        
        for (i, table) in table_sections.iter().enumerate() {
            eprintln!("E01::open -   Table {}: {} chunks, base_offset={}, first_offset={}, last_offset={}", 
                     i, table.chunk_count, table.base_offset,
                     table.offsets.first().unwrap_or(&0),
                     table.offsets.last().unwrap_or(&0));
        }

        Ok(E01Session {
            files,
            volume,
            table_sections,
            segment_sizes,
        })
    }

    fn read_chunk(&mut self, chunk_index: usize) -> Result<Vec<u8>, String> {
        // Find which table section contains this chunk
        let mut cumulative_chunks = 0u32;
        let mut target_table: Option<&TableSection> = None;
        let mut chunk_in_table = 0usize;

        for table in &self.table_sections {
            if chunk_index < (cumulative_chunks + table.chunk_count) as usize {
                target_table = Some(table);
                chunk_in_table = chunk_index - cumulative_chunks as usize;
                break;
            }
            cumulative_chunks += table.chunk_count;
        }

        let table = target_table.ok_or(format!("Chunk {} not found in tables", chunk_index))?;

        if chunk_in_table >= table.offsets.len() {
            return Err(format!("Chunk {} offset not available: chunk_in_table={}, offsets.len()={}", 
                chunk_index, chunk_in_table, table.offsets.len()));
        }

        // Get chunk offset and size
        let chunk_offset = table.offsets[chunk_in_table];
        
        // Sparse chunk detection: offset=0 means chunk is all zeros
        if chunk_offset == 0 {
            // Return 64KB of zeros (standard E01 chunk size)
            return Ok(vec![0u8; 64 * 1024]);
        }
        
        // E01 format: bit 31 indicates compression
        // Bit 31 SET (1) = chunk IS compressed
        // Bit 31 CLEAR (0) = chunk is NOT compressed  
        let is_compressed = (chunk_offset & 0x80000000) != 0;
        let offset_value = chunk_offset & 0x7FFFFFFF;
        
        // CRITICAL: Offsets in each table are RELATIVE to that table's sectors section
        // Each table has a sectors_start that points to where its chunk data begins
        // Formula: global_offset = sectors_start + base_offset + offset_value
        let global_offset = table.sectors_start + table.base_offset + offset_value;
        
        // Determine which segment file contains this offset
        let (segment_index, offset_in_segment) = self.calculate_segment_position(global_offset)?;
        
        // Debug first few chunks
        if chunk_index < 10 {
            eprintln!("Chunk {}: offset={:#x}, compressed={}, masked={}, sectors_start={}, global={}, segment={}, offset_in_seg={}", 
                     chunk_index, chunk_offset, is_compressed, offset_value, table.sectors_start, global_offset, segment_index, offset_in_segment);
        }
        
        // For uncompressed chunks, size is the standard chunk size
        // For compressed chunks, try to use next offset if available
        let chunk_size = if is_compressed {
            if chunk_in_table + 1 < table.offsets.len() {
                let next_chunk_offset = table.offsets[chunk_in_table + 1] & 0x7FFFFFFF;
                
                if next_chunk_offset > offset_value {
                    (next_chunk_offset - offset_value) as usize
                } else {
                    // Can't use next offset, default to uncompressed size
                    (self.volume.sectors_per_chunk * self.volume.bytes_per_sector) as usize
                }
            } else {
                (self.volume.sectors_per_chunk * self.volume.bytes_per_sector) as usize
            }
        } else {
            // Uncompressed: exact chunk size
            (self.volume.sectors_per_chunk * self.volume.bytes_per_sector) as usize
        };
        
        // Sanity check
        let max_reasonable_size = 128 * 1024 * 1024;
        if chunk_size > max_reasonable_size || chunk_size == 0 {
            return Err(format!(
                "Invalid chunk size {} at offset {} in segment {}",
                chunk_size, offset_in_segment, table.segment_index
            ));
        }

        // Read chunk data from the specific segment file
        let mut chunk_data = vec![0u8; chunk_size];
        self.read_at_segment(table.segment_index, offset_in_segment, &mut chunk_data)?;

        // Decompress if needed
        if is_compressed {
            let mut decompressed = Vec::new();
            let mut decoder = ZlibDecoder::new(&chunk_data[..]);
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| format!("Failed to decompress chunk: {e}"))?;

            // Verify size
            let expected_size = (self.volume.sectors_per_chunk * self.volume.bytes_per_sector) as usize;
            if decompressed.len() != expected_size {
                return Err(format!(
                    "Decompressed chunk size mismatch: got {}, expected {}",
                    decompressed.len(),
                    expected_size
                ));
            }

            Ok(decompressed)
        } else {
            Ok(chunk_data)
        }
    }

    fn calculate_segment_position(&self, global_offset: u64) -> Result<(usize, u64), String> {
        // Convert global offset to (segment_index, offset_within_segment)
        // Segments form a continuous address space: [0..size0), [size0..size0+size1), etc.
        let mut cumulative_offset = 0u64;
        
        for (segment_index, &segment_size) in self.segment_sizes.iter().enumerate() {
            let segment_end = cumulative_offset + segment_size;
            
            if global_offset < segment_end {
                let offset_in_segment = global_offset - cumulative_offset;
                return Ok((segment_index, offset_in_segment));
            }
            
            cumulative_offset = segment_end;
        }
        
        Err(format!(
            "Global offset {} exceeds total size {} across {} segments",
            global_offset, cumulative_offset, self.segment_sizes.len()
        ))
    }

    fn read_at_segment(&mut self, segment_index: usize, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        // Read from a specific segment file at the given offset
        if segment_index >= self.files.len() {
            return Err(format!(
                "Segment index {} is beyond available segments ({})",
                segment_index, self.files.len()
            ));
        }

        self.files[segment_index]
            .seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Failed to seek in segment {}: {e}", segment_index))?;

        self.files[segment_index]
            .read_exact(buf)
            .map_err(|e| format!("Failed to read from segment {}: {e}", segment_index))?;

        Ok(())
    }

    #[allow(dead_code)]
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        // Determine which segment file contains this offset using proper calculation
        let (segment_index, offset_in_segment) = self.calculate_segment_position(offset)?;

        self.files[segment_index]
            .seek(SeekFrom::Start(offset_in_segment))
            .map_err(|e| format!("Failed to seek: {e}"))?;

        self.files[segment_index]
            .read_exact(buf)
            .map_err(|e| format!("Failed to read data: {e}"))?;

        Ok(())
    }
}

fn read_table_section(file: &mut File, offset: u64, _size: u64) -> Result<TableSection, String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek to table section: {e}"))?;

    // DEBUG: Read first 64 bytes as hex to see full table header structure
    let mut debug_bytes = [0u8; 64];
    file.read_exact(&mut debug_bytes)
        .map_err(|e| format!("Failed to read debug bytes: {e}"))?;
    eprintln!("E01::read_table - First 64 bytes at offset {}: {:02x?}", offset, &debug_bytes);
    
    // Reset to start of table data
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek back to table: {e}"))?;

    let chunk_count = read_u32(file)?;
    eprintln!("E01::read_table - chunk_count: {}", chunk_count);
    
    // Skip padding
    file.seek(SeekFrom::Current(12))
        .map_err(|e| format!("Failed to skip padding: {e}"))?;

    let base_offset = read_u64(file)?;
    eprintln!("E01::read_table - base_offset: {}", base_offset);
    
    // Skip more reserved bytes
    file.seek(SeekFrom::Current(4))
        .map_err(|e| format!("Failed to skip reserved: {e}"))?;

    let checksum = read_u32(file)?;
    eprintln!("E01::read_table - checksum: 0x{:08x}", checksum);

    // Skip additional 16 bytes of reserved/padding data before offset array
    file.seek(SeekFrom::Current(16))
        .map_err(|e| format!("Failed to skip extra padding: {e}"))?;
    
    eprintln!("E01::read_table - Reading offset array starting at file position {}", 
             file.stream_position().unwrap_or(0));

    // E01 tables store 32-bit RELATIVE offsets, not 64-bit absolute offsets!
    let mut offsets = Vec::with_capacity(chunk_count as usize);
    for i in 0..chunk_count {
        let chunk_offset = read_u32(file)? as u64; // Read as u32, convert to u64
        if i < 10 {
            eprintln!("E01::read_table - offset[{}]: {} (relative)", i, chunk_offset);
        }
        offsets.push(chunk_offset);
    }

    Ok(TableSection {
        chunk_count,
        base_offset,
        checksum,
        offsets,
        sectors_start: 0, // Will be set by caller
        segment_index: 0, // Will be set by caller
    })
}
