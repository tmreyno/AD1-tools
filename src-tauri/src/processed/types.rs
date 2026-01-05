//! Types for processed forensic databases
//!
//! These represent parsed examination results, not raw evidence.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The type/source of processed database
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessedDbType {
    /// Magnet AXIOM (.mfdb, Case.mcfc)
    MagnetAxiom,
    /// Cellebrite Physical Analyzer (extracted UFDR contents)
    CellebritePA,
    /// X-Ways Forensics (.ctx case container)
    XWays,
    /// Autopsy (.aut case file)
    Autopsy,
    /// EnCase (.case, .LEF)
    EnCase,
    /// FTK (AccessData/Exterro)
    FTK,
    /// Generic SQLite forensic database
    GenericSqlite,
    /// Unknown processed database type
    Unknown,
}

impl ProcessedDbType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProcessedDbType::MagnetAxiom => "Magnet AXIOM",
            ProcessedDbType::CellebritePA => "Cellebrite PA",
            ProcessedDbType::XWays => "X-Ways",
            ProcessedDbType::Autopsy => "Autopsy",
            ProcessedDbType::EnCase => "EnCase",
            ProcessedDbType::FTK => "FTK",
            ProcessedDbType::GenericSqlite => "SQLite Database",
            ProcessedDbType::Unknown => "Unknown",
        }
    }
    
    pub fn icon(&self) -> &'static str {
        match self {
            ProcessedDbType::MagnetAxiom => "🧲",
            ProcessedDbType::CellebritePA => "📱",
            ProcessedDbType::XWays => "🔬",
            ProcessedDbType::Autopsy => "🔍",
            ProcessedDbType::EnCase => "📦",
            ProcessedDbType::FTK => "🗃️",
            ProcessedDbType::GenericSqlite => "🗄️",
            ProcessedDbType::Unknown => "❓",
        }
    }
}

/// Information about a processed database folder/file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedDbInfo {
    /// Type of processed database
    pub db_type: ProcessedDbType,
    /// Root path to the database folder or file
    pub path: PathBuf,
    /// Display name (case name, folder name, etc.)
    pub name: String,
    /// Case number if detected
    pub case_number: Option<String>,
    /// Examiner name if detected
    pub examiner: Option<String>,
    /// Date created/processed
    pub created_date: Option<String>,
    /// Total size on disk
    pub total_size: u64,
    /// Number of artifacts found (if scanned)
    pub artifact_count: Option<u32>,
    /// Database files within this processed DB
    pub database_files: Vec<DatabaseFile>,
    /// Notes or description
    pub notes: Option<String>,
}

/// Individual database file within a processed database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseFile {
    /// File path relative to root
    pub path: PathBuf,
    /// File name
    pub name: String,
    /// File size
    pub size: u64,
    /// What this database contains
    pub contents: DatabaseContents,
}

/// What type of data a database file contains
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatabaseContents {
    /// Main case database
    CaseInfo,
    /// Parsed artifacts (browser, chat, etc.)
    Artifacts,
    /// File system metadata
    FileSystem,
    /// Keyword search results
    Keywords,
    /// Hash values and sets
    Hashes,
    /// Media (thumbnails, carved files)
    Media,
    /// Timeline data
    Timeline,
    /// Bookmarks and tags
    Bookmarks,
    /// Reports
    Reports,
    /// Configuration
    Config,
    /// Unknown
    Unknown,
}

impl DatabaseContents {
    pub fn as_str(&self) -> &'static str {
        match self {
            DatabaseContents::CaseInfo => "Case Information",
            DatabaseContents::Artifacts => "Artifacts",
            DatabaseContents::FileSystem => "File System",
            DatabaseContents::Keywords => "Keywords",
            DatabaseContents::Hashes => "Hashes",
            DatabaseContents::Media => "Media",
            DatabaseContents::Timeline => "Timeline",
            DatabaseContents::Bookmarks => "Bookmarks",
            DatabaseContents::Reports => "Reports",
            DatabaseContents::Config => "Configuration",
            DatabaseContents::Unknown => "Unknown",
        }
    }
}

/// Summary of a processed database scan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessedDbSummary {
    /// Total processed databases found
    pub total_count: usize,
    /// Count by type
    pub by_type: std::collections::HashMap<String, usize>,
    /// Total size of all databases
    pub total_size: u64,
}
