//! Detection logic for processed forensic databases
//!
//! Identifies AXIOM, Cellebrite PA, X-Ways, Autopsy, EnCase, FTK databases.

use std::fs;
use std::path::Path;
use tracing::debug;

use super::types::*;

/// Detect if a path is a processed database and what type
pub fn detect_processed_db(path: &Path) -> Option<ProcessedDbType> {
    if !path.exists() {
        return None;
    }
    
    // Check for Magnet AXIOM
    if is_axiom_database(path) {
        return Some(ProcessedDbType::MagnetAxiom);
    }
    
    // Check for Cellebrite PA extracted data
    if is_cellebrite_pa(path) {
        return Some(ProcessedDbType::CellebritePA);
    }
    
    // Check for X-Ways
    if is_xways(path) {
        return Some(ProcessedDbType::XWays);
    }
    
    // Check for Autopsy
    if is_autopsy(path) {
        return Some(ProcessedDbType::Autopsy);
    }
    
    // Check for EnCase
    if is_encase(path) {
        return Some(ProcessedDbType::EnCase);
    }
    
    // Check for FTK
    if is_ftk(path) {
        return Some(ProcessedDbType::FTK);
    }
    
    None
}

/// Check if path is a Magnet AXIOM processed database
/// 
/// AXIOM structure:
/// - Folder containing Case.mfdb or Case.mcfc files
/// - Folder name starts with "AXIOM"
/// - Contains Case Information.xml or Case Information.txt
/// 
/// Note: Folders named "Processed.Database" are containers for cases,
/// not cases themselves, so we check for actual AXIOM files.
fn is_axiom_database(path: &Path) -> bool {
    if path.is_dir() {
        let name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let name_lower = name.to_lowercase();
        
        // Check for AXIOM-specific files first (most reliable)
        let case_mcfc = path.join("Case.mcfc");
        let case_mfdb = path.join("Case.mfdb");
        let case_info_xml = path.join("Case Information.xml");
        let case_info_txt = path.join("Case Information.txt");
        
        if case_mcfc.exists() {
            debug!("AXIOM detected by Case.mcfc: {}", path.display());
            return true;
        }
        
        if case_mfdb.exists() {
            debug!("AXIOM detected by Case.mfdb: {}", path.display());
            return true;
        }
        
        if case_info_xml.exists() || case_info_txt.exists() {
            debug!("AXIOM detected by Case Information file: {}", path.display());
            return true;
        }
        
        // Folder name starting with "AXIOM" is a strong indicator,
        // but only if it's not the parent container folder
        if name_lower.starts_with("axiom") && !name_lower.contains("processed") {
            // Double check it has some AXIOM-related content
            let has_mfdb = fs::read_dir(path)
                .ok()
                .map(|entries| {
                    entries.filter_map(|e| e.ok())
                        .any(|e| {
                            let ext = e.path().extension().map(|x| x.to_string_lossy().to_lowercase());
                            ext.as_deref() == Some("mfdb") || ext.as_deref() == Some("mcfc")
                        })
                })
                .unwrap_or(false);
            
            if has_mfdb {
                debug!("AXIOM detected by folder name + mfdb: {}", name);
                return true;
            }
        }
        
        // Check for any .mfdb file in the folder (but not in "Processed.Database" container folders)
        if !name_lower.contains("processed.database") && !name_lower.contains("processed database") {
            let mfdb_exists = fs::read_dir(path)
                .ok()
                .map(|entries| {
                    entries.filter_map(|e| e.ok())
                        .any(|e| e.path().extension().map(|ext| ext == "mfdb").unwrap_or(false))
                })
                .unwrap_or(false);
            
            if mfdb_exists {
                debug!("AXIOM detected by .mfdb file: {}", path.display());
                return true;
            }
        }
    } else if path.is_file() {
        // Direct .mfdb file
        if let Some(ext) = path.extension() {
            if ext == "mfdb" || ext == "mcfc" {
                return true;
            }
        }
    }
    
    false
}

/// Check if path is Cellebrite PA extracted data
///
/// PA structure:
/// - Contains UFD Report/ or UFED_Reader/ folder
/// - Has cellebrite.db or pa.db
/// - XML reports
fn is_cellebrite_pa(path: &Path) -> bool {
    if path.is_dir() {
        // Check for PA-specific folders
        let ufd_report = path.join("UFD Report");
        let ufed_reader = path.join("UFED_Reader");
        let report_xml = path.join("report.xml");
        
        if ufd_report.exists() || ufed_reader.exists() || report_xml.exists() {
            return true;
        }
        
        // Check for cellebrite database files
        let has_cellebrite_db = fs::read_dir(path)
            .ok()
            .map(|entries| {
                entries.filter_map(|e| e.ok())
                    .any(|e| {
                        let name = e.file_name().to_string_lossy().to_lowercase();
                        name.contains("cellebrite") || name == "pa.db"
                    })
            })
            .unwrap_or(false);
        
        if has_cellebrite_db {
            return true;
        }
    }
    
    false
}

/// Check if path is X-Ways case
fn is_xways(path: &Path) -> bool {
    if path.is_file() {
        if let Some(ext) = path.extension() {
            // X-Ways case container
            if ext == "ctx" {
                return true;
            }
        }
    } else if path.is_dir() {
        // Check for X-Ways files
        let has_xways = fs::read_dir(path)
            .ok()
            .map(|entries| {
                entries.filter_map(|e| e.ok())
                    .any(|e| {
                        e.path().extension()
                            .map(|ext| ext == "ctx" || ext == "xfc")
                            .unwrap_or(false)
                    })
            })
            .unwrap_or(false);
        
        if has_xways {
            return true;
        }
    }
    
    false
}

/// Check if path is Autopsy case
fn is_autopsy(path: &Path) -> bool {
    if path.is_file() {
        if let Some(ext) = path.extension() {
            if ext == "aut" {
                return true;
            }
        }
    } else if path.is_dir() {
        // Check for Autopsy case folder structure
        let autopsy_db = path.join("autopsy.db");
        let case_aut = fs::read_dir(path)
            .ok()
            .map(|entries| {
                entries.filter_map(|e| e.ok())
                    .any(|e| {
                        e.path().extension()
                            .map(|ext| ext == "aut")
                            .unwrap_or(false)
                    })
            })
            .unwrap_or(false);
        
        if autopsy_db.exists() || case_aut {
            return true;
        }
    }
    
    false
}

/// Check if path is EnCase case
fn is_encase(path: &Path) -> bool {
    if path.is_file() {
        if let Some(ext) = path.extension() {
            // EnCase case file or logical evidence
            if ext == "case" || ext == "LEF" || ext == "L01" {
                // Note: L01 is also handled by EWF, but in case context it's EnCase
                return ext == "case" || ext == "LEF";
            }
        }
    } else if path.is_dir() {
        // Check for EnCase case structure
        let has_encase = fs::read_dir(path)
            .ok()
            .map(|entries| {
                entries.filter_map(|e| e.ok())
                    .any(|e| {
                        e.path().extension()
                            .map(|ext| ext == "case" || ext == "LEF")
                            .unwrap_or(false)
                    })
            })
            .unwrap_or(false);
        
        if has_encase {
            return true;
        }
    }
    
    false
}

/// Check if path is FTK case
fn is_ftk(path: &Path) -> bool {
    if path.is_dir() {
        // FTK has .ftk case files
        let has_ftk = fs::read_dir(path)
            .ok()
            .map(|entries| {
                entries.filter_map(|e| e.ok())
                    .any(|e| {
                        let name = e.file_name().to_string_lossy().to_lowercase();
                        e.path().extension().map(|ext| ext == "ftk").unwrap_or(false)
                            || name.contains("ftk")
                    })
            })
            .unwrap_or(false);
        
        if has_ftk {
            return true;
        }
    }
    
    false
}

/// Scan a directory for processed databases
pub fn scan_for_processed_dbs(root: &Path, recursive: bool) -> Vec<ProcessedDbInfo> {
    let mut results = Vec::new();
    
    if !root.exists() || !root.is_dir() {
        return results;
    }
    
    debug!("Scanning for processed databases: {}", root.display());
    
    // Check if root itself is a processed DB
    if let Some(db_type) = detect_processed_db(root) {
        if let Some(info) = get_processed_db_info(root, db_type) {
            results.push(info);
            return results; // Don't recurse into a processed DB
        }
    }
    
    // Scan directory entries
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            
            if let Some(db_type) = detect_processed_db(&path) {
                if let Some(info) = get_processed_db_info(&path, db_type) {
                    results.push(info);
                }
            } else if recursive && path.is_dir() {
                // Recurse into subdirectories
                results.extend(scan_for_processed_dbs(&path, true));
            }
        }
    }
    
    results
}

/// Get detailed info about a processed database
pub fn get_processed_db_info(path: &Path, db_type: ProcessedDbType) -> Option<ProcessedDbInfo> {
    let name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Unknown")
        .to_string();
    
    // Calculate total size
    let total_size = calculate_dir_size(path);
    
    // Find database files
    let database_files = find_database_files(path, db_type);
    
    // Try to extract case info from the name
    let case_number = extract_case_number(&name);
    
    Some(ProcessedDbInfo {
        db_type,
        path: path.to_path_buf(),
        name,
        case_number,
        examiner: None,
        created_date: None,
        total_size,
        artifact_count: None,
        database_files,
        notes: None,
    })
}

/// Calculate total size of a directory
fn calculate_dir_size(path: &Path) -> u64 {
    if path.is_file() {
        return path.metadata().map(|m| m.len()).unwrap_or(0);
    }
    
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.filter_map(|e| e.ok()) {
            let entry_path = entry.path();
            if entry_path.is_file() {
                total += entry_path.metadata().map(|m| m.len()).unwrap_or(0);
            } else if entry_path.is_dir() {
                total += calculate_dir_size(&entry_path);
            }
        }
    }
    total
}

/// Find database files within a processed database
fn find_database_files(path: &Path, db_type: ProcessedDbType) -> Vec<DatabaseFile> {
    let mut files = Vec::new();
    
    if !path.is_dir() {
        // Single file
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            files.push(DatabaseFile {
                path: path.to_path_buf(),
                name: name.to_string(),
                size: path.metadata().map(|m| m.len()).unwrap_or(0),
                contents: classify_database_contents(name, db_type),
            });
        }
        return files;
    }
    
    // Scan for database files
    let extensions = match db_type {
        ProcessedDbType::MagnetAxiom => vec!["mfdb", "db", "sqlite", "mcfc"],
        ProcessedDbType::CellebritePA => vec!["db", "sqlite", "xml"],
        ProcessedDbType::XWays => vec!["ctx", "xfc", "db"],
        ProcessedDbType::Autopsy => vec!["db", "aut"],
        ProcessedDbType::EnCase => vec!["case", "LEF", "db"],
        ProcessedDbType::FTK => vec!["ftk", "db"],
        _ => vec!["db", "sqlite"],
    };
    
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.filter_map(|e| e.ok()) {
            let entry_path = entry.path();
            if entry_path.is_file() {
                if let Some(ext) = entry_path.extension().and_then(|e| e.to_str()) {
                    if extensions.contains(&ext) {
                        if let Some(name) = entry_path.file_name().and_then(|n| n.to_str()) {
                            files.push(DatabaseFile {
                                path: entry_path.clone(),
                                name: name.to_string(),
                                size: entry_path.metadata().map(|m| m.len()).unwrap_or(0),
                                contents: classify_database_contents(name, db_type),
                            });
                        }
                    }
                }
            }
        }
    }
    
    files
}

/// Classify what a database file contains based on its name
fn classify_database_contents(name: &str, _db_type: ProcessedDbType) -> DatabaseContents {
    let lower = name.to_lowercase();
    
    if lower.contains("case") || lower.contains("mcfc") {
        DatabaseContents::CaseInfo
    } else if lower.contains("artifact") {
        DatabaseContents::Artifacts
    } else if lower.contains("file") || lower.contains("fs") {
        DatabaseContents::FileSystem
    } else if lower.contains("keyword") || lower.contains("search") {
        DatabaseContents::Keywords
    } else if lower.contains("hash") {
        DatabaseContents::Hashes
    } else if lower.contains("media") || lower.contains("thumb") {
        DatabaseContents::Media
    } else if lower.contains("timeline") || lower.contains("time") {
        DatabaseContents::Timeline
    } else if lower.contains("bookmark") || lower.contains("tag") {
        DatabaseContents::Bookmarks
    } else if lower.contains("report") {
        DatabaseContents::Reports
    } else if lower.contains("config") || lower.contains("setting") {
        DatabaseContents::Config
    } else {
        DatabaseContents::Unknown
    }
}

/// Try to extract case number from a name string
fn extract_case_number(name: &str) -> Option<String> {
    // Common patterns: 24-042, 2024-001, CASE-001, etc.
    let re_patterns = [
        r"\d{2,4}-\d{3,4}",  // 24-042 or 2024-001
        r"CASE-?\d+",        // CASE001 or CASE-001
    ];
    
    for pattern in re_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(m) = re.find(name) {
                return Some(m.as_str().to_string());
            }
        }
    }
    
    None
}
