//! Companion log file parsing for forensic containers
//!
//! This module handles parsing of companion log files from various forensic tools:
//! - FTK Imager
//! - dc3dd / dcfldd
//! - Guymager
//! - Forensic MD5
//! - Various hash files (.md5, .sha1, .sha256)

use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use regex::Regex;
use tracing::debug;

use super::types::{CompanionLogInfo, StoredHash, SegmentHash};

/// Pre-compiled regex for matching hex hash values (32-128 chars)
/// Compiled once on first use via OnceLock
fn hash_regex() -> &'static Regex {
    static HASH_REGEX: OnceLock<Regex> = OnceLock::new();
    HASH_REGEX.get_or_init(|| {
        Regex::new(r"[a-fA-F0-9]{32,128}").expect("Invalid hash regex")
    })
}

/// Find and parse companion log file (e.g., .txt file created by FTK Imager, dc3dd, etc.)
pub fn find_companion_log(image_path: &str) -> Option<CompanionLogInfo> {
    debug!("Looking for companion log for: {}", image_path);
    let path = Path::new(image_path);
    let parent = path.parent()?;
    let stem = path.file_stem()?.to_str()?;
    let filename = path.file_name()?.to_str()?;
    
    // For segmented raw images (.001, .002), get the base name without segment number
    let base_stem = if let Some(dot_pos) = stem.rfind('.') {
        let ext = &stem[dot_pos + 1..];
        if ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit()) {
            // This is like "image.001" where stem is "image"
            stem.to_string()
        } else {
            stem.to_string()
        }
    } else {
        stem.to_string()
    };
    
    // Also handle case where filename is "image.001" - stem would be "image"
    // But if filename is "image.dd.001" - stem would be "image.dd"
    let numeric_ext = filename.rsplit('.').next()
        .map(|e| e.len() == 3 && e.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false);
    
    let base_for_log = if numeric_ext {
        // Remove numeric extension from filename for log search
        &filename[..filename.len() - 4]
    } else {
        filename
    };
    
    // Common companion log file patterns for various forensic tools:
    let mut candidate_paths = vec![
        // Standard patterns
        parent.join(format!("{}.txt", filename)),           // image.ad1.txt, image.dd.txt
        parent.join(format!("{}.txt", stem)),               // image.txt
        parent.join(format!("{}_info.txt", stem)),          // image_info.txt
        parent.join(format!("{}.log", filename)),           // image.ad1.log
        parent.join(format!("{}.log", stem)),               // image.log
        parent.join(format!("{}.LOG", stem)),               // image.LOG (uppercase for Forensic MD5)
        
        // AD1 / FTK Imager specific patterns
        parent.join(format!("{}.ad1.txt", stem)),           // image.ad1.txt (FTK Imager)
        parent.join(format!("{}1.txt", stem)),              // image1.txt (if stem ends in number)
        parent.join(format!("{}_img1.ad1.txt", stem.trim_end_matches("_img1"))), // For _img1 suffix
        
        // E01 / EnCase specific patterns  
        parent.join(format!("{}.E01.txt", stem)),           // image.E01.txt
        parent.join(format!("{}.e01.txt", stem)),           // image.e01.txt
        
        // For segmented raw images
        parent.join(format!("{}.txt", base_for_log)),       // image.dd.txt for image.dd.001
        parent.join(format!("{}.log", base_for_log)),       // image.dd.log for image.dd.001
        parent.join(format!("{}.LOG", base_for_log)),       // image.dd.LOG for image.dd.001
        parent.join(format!("{}_info.txt", base_for_log)),  // image.dd_info.txt
        
        // dc3dd / dcfldd patterns
        parent.join(format!("{}.hash", stem)),              // image.hash
        parent.join(format!("{}.md5", stem)),               // image.md5
        parent.join(format!("{}.sha1", stem)),              // image.sha1
        parent.join(format!("{}.sha256", stem)),            // image.sha256
        parent.join(format!("{}_hash.txt", stem)),          // image_hash.txt
        parent.join(format!("{}_hashes.txt", stem)),        // image_hashes.txt
        
        // Guymager patterns
        parent.join(format!("{}.info", stem)),              // image.info
        parent.join(format!("{}.info", filename)),          // image.dd.info
        
        // MacQuisition / Paladin / other tools
        parent.join(format!("{}_acquisition.txt", stem)),   // image_acquisition.txt
        parent.join(format!("{}_acquisition.log", stem)),   // image_acquisition.log
    ];
    
    // Also try with base_stem for segmented images
    if base_stem != stem {
        candidate_paths.push(parent.join(format!("{}.txt", base_stem)));
        candidate_paths.push(parent.join(format!("{}.log", base_stem)));
        candidate_paths.push(parent.join(format!("{}.LOG", base_stem)));  // SCHARDT.LOG
        candidate_paths.push(parent.join(format!("{}_info.txt", base_stem)));
    }
    
    for log_path in candidate_paths {
        if log_path.exists() {
            debug!("Found companion log candidate: {:?}", log_path);
            if let Ok(info) = parse_companion_log(&log_path) {
                debug!("Successfully parsed companion log: {:?}", log_path);
                return Some(info);
            }
        }
    }
    
    debug!("No companion log found for: {}", image_path);
    None
}

/// Parse companion log file from various forensic tools (FTK Imager, dc3dd, dcfldd, Guymager, etc.)
fn parse_companion_log(log_path: &Path) -> Result<CompanionLogInfo, String> {
    let content = fs::read_to_string(log_path)
        .map_err(|e| format!("Failed to read log file: {}", e))?;
    
    let mut info = CompanionLogInfo {
        log_path: log_path.to_string_lossy().to_string(),
        created_by: None,
        case_number: None,
        evidence_number: None,
        unique_description: None,
        examiner: None,
        notes: None,
        acquisition_started: None,
        acquisition_finished: None,
        verification_started: None,
        verification_finished: None,
        stored_hashes: Vec::new(),
        segment_list: Vec::new(),
        segment_hashes: Vec::new(),
    };
    
    // Detect file format based on content
    let content_lower = content.to_lowercase();
    let is_dc3dd = content_lower.contains("dc3dd") || content_lower.contains("dcfldd");
    let is_guymager = content_lower.contains("guymager");
    let is_forensic_md5 = content_lower.contains("forensic md5") || 
                          content.contains("MD5 Value:") ||
                          content.lines().any(|l| l.trim().starts_with("* ") && l.contains("From:") && l.contains("To:"));
    let is_hash_only = log_path.extension()
        .map(|e| matches!(e.to_str(), Some("md5" | "sha1" | "sha256" | "hash")))
        .unwrap_or(false);
    
    // Handle hash-only files (just hash value, maybe with filename)
    if is_hash_only {
        if let Some(hash_info) = parse_simple_hash_file(&content, log_path) {
            info.stored_hashes.push(hash_info);
            return Ok(info);
        }
    }
    
    // Handle Forensic MD5 per-segment hash format
    if is_forensic_md5 {
        if let Some(segment_hashes) = parse_forensic_md5_segments(&content) {
            info.segment_hashes = segment_hashes;
            info.created_by = Some("Forensic MD5".to_string());
        }
    }
    
    // Parse line by line
    let mut in_segment_list = false;
    let mut in_computed_hashes = false;
    let mut in_verification_results = false;
    
    for line in content.lines() {
        let line = line.trim();
        let line_lower = line.to_lowercase();
        
        // Skip empty lines
        if line.is_empty() {
            continue;
        }
        
        // Check for section headers
        if line.starts_with("Created By ") || line_lower.starts_with("created by:") {
            let value = line.split_once(':').or(line.split_once(' '))
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_else(|| line.to_string());
            if !value.is_empty() && value != "By" {
                info.created_by = Some(value);
            }
            continue;
        }
        
        // dc3dd/dcfldd output parsing
        if is_dc3dd {
            // Patterns like "md5 hash: abc123..." or "sha256: abc123..."
            if let Some(hash_info) = parse_dc3dd_hash_line(line) {
                info.stored_hashes.push(hash_info);
                continue;
            }
            
            // Input/output device info
            if line_lower.starts_with("input device:") || line_lower.starts_with("input:") {
                if let Some((_, v)) = line.split_once(':') {
                    info.unique_description = Some(v.trim().to_string());
                }
                continue;
            }
        }
        
        // Guymager output parsing
        if is_guymager {
            if let Some(hash_info) = parse_guymager_hash_line(line) {
                info.stored_hashes.push(hash_info);
                continue;
            }
        }
        
        if line == "Segment list:" || line == "[Segment List]" {
            in_segment_list = true;
            in_computed_hashes = false;
            in_verification_results = false;
            continue;
        }
        
        if line.starts_with("[Computed Hashes]") || line == "Computed Hashes:" {
            in_computed_hashes = true;
            in_segment_list = false;
            in_verification_results = false;
            continue;
        }
        
        if line.starts_with("Image Verification Results:") || line == "[Verification Results]" {
            in_verification_results = true;
            in_segment_list = false;
            in_computed_hashes = false;
            continue;
        }
        
        // Parse segment list entries
        if in_segment_list && !line.is_empty() && !line.starts_with("Image") && !line.starts_with("[") {
            info.segment_list.push(line.to_string());
            continue;
        }
        
        // Parse hash entries (both computed and verification)
        if in_computed_hashes || in_verification_results {
            if let Some(hash_info) = parse_hash_line(line, in_verification_results) {
                // Check if we already have this algorithm - update with verification status
                if let Some(existing) = info.stored_hashes.iter_mut()
                    .find(|h| h.algorithm.to_lowercase() == hash_info.algorithm.to_lowercase()) 
                {
                    if hash_info.verified.is_some() {
                        existing.verified = hash_info.verified;
                    }
                } else {
                    info.stored_hashes.push(hash_info);
                }
                continue;
            }
        }
        
        // Parse key-value pairs
        if let Some((key, value)) = parse_key_value(line) {
            match key.to_lowercase().as_str() {
                "case number" | "case" | "case_number" => info.case_number = Some(value),
                "evidence number" | "evidence" | "evidence_number" => info.evidence_number = Some(value),
                "unique description" | "description" => info.unique_description = Some(value),
                "examiner" | "examiner name" => info.examiner = Some(value),
                "notes" | "note" | "comments" => info.notes = Some(value),
                "acquisition started" | "start time" | "started" => info.acquisition_started = Some(value),
                "acquisition finished" | "end time" | "finished" | "completed" => info.acquisition_finished = Some(value),
                "verification started" => info.verification_started = Some(value),
                "verification finished" => info.verification_finished = Some(value),
                "source" | "source device" | "input" => {
                    if info.unique_description.is_none() {
                        info.unique_description = Some(value);
                    }
                }
                "tool" | "program" | "software" => {
                    if info.created_by.is_none() {
                        info.created_by = Some(value);
                    }
                }
                _ => {
                    // Check if this looks like a hash line
                    if let Some(hash_info) = parse_hash_line(line, false) {
                        info.stored_hashes.push(hash_info);
                    }
                }
            }
        }
    }
    
    // Only return if we found useful information
    if info.stored_hashes.is_empty() 
        && info.case_number.is_none() 
        && info.evidence_number.is_none()
        && info.examiner.is_none()
        && info.created_by.is_none()
        && info.unique_description.is_none()
        && info.segment_list.is_empty()
        && info.segment_hashes.is_empty()
    {
        return Err("No useful information found in log file".to_string());
    }
    
    Ok(info)
}

/// Parse a simple hash file (just hash value, possibly with filename)
fn parse_simple_hash_file(content: &str, log_path: &Path) -> Option<StoredHash> {
    let ext = log_path.extension()?.to_str()?.to_lowercase();
    let algorithm = match ext.as_str() {
        "md5" => "MD5",
        "sha1" => "SHA-1",
        "sha256" => "SHA-256",
        "sha512" => "SHA-512",
        "hash" => return parse_hash_from_content(content, log_path),
        _ => return None,
    };
    
    // Extract hash from content (might be "hash  filename" or just "hash")
    let hash = hash_regex().find(content.trim())?.as_str().to_lowercase();
    
    // Get file modification time as timestamp
    let timestamp = log_path.metadata().ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let datetime: chrono::DateTime<chrono::Utc> = t.into();
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        });
    
    Some(StoredHash {
        algorithm: algorithm.to_string(),
        hash,
        verified: None,
        timestamp,
        source: Some("companion".to_string()),
    })
}

/// Parse hash from generic hash file content
fn parse_hash_from_content(content: &str, log_path: &Path) -> Option<StoredHash> {
    let hash = hash_regex().find(content.trim())?.as_str().to_lowercase();
    
    // Guess algorithm from hash length
    let algorithm = match hash.len() {
        32 => "MD5",
        40 => "SHA-1",
        64 => "SHA-256",
        128 => "SHA-512",
        _ => return None,
    };
    
    // Get file modification time as timestamp
    let timestamp = log_path.metadata().ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let datetime: chrono::DateTime<chrono::Utc> = t.into();
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        });
    
    Some(StoredHash {
        algorithm: algorithm.to_string(),
        hash,
        verified: None,
        timestamp,
        source: Some("companion".to_string()),
    })
}

/// Parse dc3dd/dcfldd style hash output
fn parse_dc3dd_hash_line(line: &str) -> Option<StoredHash> {
    let line_lower = line.to_lowercase();
    
    // Patterns:
    // "md5 hash: abc123..."
    // "sha256 hash of input: abc123..."
    // "abc123... (md5)"
    
    let algorithms = [
        ("md5", "MD5"),
        ("sha1", "SHA-1"),
        ("sha-1", "SHA-1"),
        ("sha256", "SHA-256"),
        ("sha-256", "SHA-256"),
        ("sha512", "SHA-512"),
        ("sha-512", "SHA-512"),
    ];
    
    for (pattern, algo_name) in &algorithms {
        if line_lower.contains(pattern) {
            if let Some(m) = hash_regex().find(line) {
                return Some(StoredHash {
                    algorithm: algo_name.to_string(),
                    hash: m.as_str().to_lowercase(),
                    verified: None,
                    timestamp: None,  // Will be set by caller from log file context
                    source: Some("companion".to_string()),
                });
            }
        }
    }
    
    None
}

/// Parse Guymager style hash output
fn parse_guymager_hash_line(line: &str) -> Option<StoredHash> {
    // Guymager patterns:
    // "MD5 hash verified source: abc123..."
    // "SHA-256 hash: abc123..."
    parse_dc3dd_hash_line(line)  // Same pattern matching works
}

/// Parse a hash line from the log file
fn parse_hash_line(line: &str, check_verified: bool) -> Option<StoredHash> {
    let line_lower = line.to_lowercase();
    
    // Common patterns:
    // "MD5 checksum:    e0778ff7fb490fc2c9c56824f9ecf448"
    // "SHA1 checksum:   93d522376d89b8dfe6bb61e4abef2bbb7102765a"
    // "MD5 checksum:    e0778ff7fb490fc2c9c56824f9ecf448 : verified"
    // "MD5: e0778ff7fb490fc2c9c56824f9ecf448"
    
    let algorithms = ["md5", "sha1", "sha256", "sha512", "sha-1", "sha-256", "sha-512"];
    
    for alg in &algorithms {
        if line_lower.contains(alg) {
            // Try to extract the hash value using pre-compiled regex
            if let Some(m) = hash_regex().find(line) {
                let hash = m.as_str().to_lowercase();
                
                // Check for verification status
                let verified = if check_verified {
                    if line_lower.contains(": verified") || line_lower.contains("verified") {
                        Some(true)
                    } else if line_lower.contains(": failed") || line_lower.contains("mismatch") {
                        Some(false)
                    } else {
                        None
                    }
                } else {
                    None
                };
                
                let algo_name = match *alg {
                    "md5" => "MD5",
                    "sha1" | "sha-1" => "SHA-1",
                    "sha256" | "sha-256" => "SHA-256",
                    "sha512" | "sha-512" => "SHA-512",
                    _ => *alg,
                };
                
                return Some(StoredHash {
                    algorithm: algo_name.to_string(),
                    hash,
                    verified,
                    timestamp: None,  // Will be set by caller from log file context
                    source: Some("companion".to_string()),
                });
            }
        }
    }
    
    None
}

/// Parse a key: value line
fn parse_key_value(line: &str) -> Option<(String, String)> {
    // Match patterns like "Case Number: 12345" or "Examiner:  John Doe"
    if let Some(colon_pos) = line.find(':') {
        let key = line[..colon_pos].trim();
        let value = line[colon_pos + 1..].trim();
        if !key.is_empty() && !value.is_empty() {
            return Some((key.to_string(), value.to_string()));
        }
    }
    None
}

/// Parse "Forensic MD5" style per-segment hash log files
/// Format:
/// * SCHARDT.001: From: 0, To: 1389747, Size: 1301248, MD5 Value:
/// * ...28A9B613 D6EEFE8A 0515EF0A 675BDEBD...
fn parse_forensic_md5_segments(content: &str) -> Option<Vec<SegmentHash>> {
    let mut segments: Vec<SegmentHash> = Vec::new();
    let mut current_segment: Option<SegmentHash> = None;
    
    for line in content.lines() {
        let line = line.trim();
        
        // Skip empty lines
        if line.is_empty() {
            continue;
        }
        
        // Look for segment header: "* SEGMENT.XXX: From: X, To: Y, Size: Z, MD5 Value:"
        if line.starts_with("* ") && line.contains(": From:") {
            // Save previous segment if any
            if let Some(seg) = current_segment.take() {
                if !seg.hash.is_empty() {
                    segments.push(seg);
                }
            }
            
            // Parse the segment header
            // Format: "* SCHARDT.001: From: 0, To: 1389747, Size: 1301248, MD5 Value:"
            let inner = &line[2..]; // Skip "* "
            
            // Extract segment name (before first ':')
            let segment_name = inner.split(':').next()?.trim().to_string();
            
            // Extract segment number from name
            let segment_number = extract_segment_number(&segment_name).unwrap_or(0);
            
            // Parse From/To/Size values
            let offset_from = extract_numeric_value(inner, "From:");
            let offset_to = extract_numeric_value(inner, "To:");
            let size = extract_numeric_value(inner, "Size:");
            
            current_segment = Some(SegmentHash {
                segment_name,
                segment_number,
                algorithm: "MD5".to_string(),
                hash: String::new(),
                offset_from,
                offset_to,
                size,
                verified: None,
            });
            continue;
        }
        
        // Look for hash value line: "* ...28A9B613 D6EEFE8A 0515EF0A 675BDEBD..."
        if line.starts_with("* ...") && current_segment.is_some() {
            // Extract hex hash (may be space-separated)
            let hash_part = &line[5..]; // Skip "* ..."
            let hash_part = hash_part.trim_end_matches("...");
            
            // Remove spaces and convert to lowercase
            let hash: String = hash_part
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect::<String>()
                .to_lowercase();
            
            if hash.len() >= 32 {
                if let Some(seg) = current_segment.as_mut() {
                    seg.hash = hash;
                }
            }
        }
    }
    
    // Don't forget the last segment
    if let Some(seg) = current_segment {
        if !seg.hash.is_empty() {
            segments.push(seg);
        }
    }
    
    if segments.is_empty() {
        None
    } else {
        Some(segments)
    }
}

/// Extract segment number from segment name (e.g., "SCHARDT.001" -> 1)
fn extract_segment_number(name: &str) -> Option<u32> {
    // Try to find numeric extension
    if let Some(dot_pos) = name.rfind('.') {
        let ext = &name[dot_pos + 1..];
        if let Ok(num) = ext.parse::<u32>() {
            return Some(num);
        }
    }
    None
}

/// Extract numeric value from a "Key: Value" pattern in a line
fn extract_numeric_value(line: &str, key: &str) -> Option<u64> {
    if let Some(pos) = line.find(key) {
        let after_key = &line[pos + key.len()..];
        // Find the number (may end at comma or end of string)
        let num_str: String = after_key
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if !num_str.is_empty() {
            return num_str.parse().ok();
        }
    }
    None
}
