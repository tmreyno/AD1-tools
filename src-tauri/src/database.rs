//! SQLite database module for FFX persistent storage
//! 
//! Handles:
//! - Sessions (open directories/workspaces)
//! - Files (discovered evidence containers)
//! - Hashes (computed hash records with timestamps)
//! - Verifications (verification audit trail)
//! - UI state (open tabs, settings)

use rusqlite::{Connection, params, Result as SqlResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

/// Database connection wrapper for thread-safe access
pub struct Database {
    conn: Mutex<Connection>,
}

// ============================================================================
// Data Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub root_path: String,
    pub created_at: String,
    pub last_opened_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub id: String,
    pub session_id: String,
    pub path: String,
    pub filename: String,
    pub container_type: String,
    pub total_size: i64,
    pub segment_count: i32,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashRecord {
    pub id: String,
    pub file_id: String,
    pub algorithm: String,
    pub hash_value: String,
    pub computed_at: String,
    pub segment_index: Option<i32>,  // NULL for full container hash
    pub segment_name: Option<String>,
    pub source: String,  // 'computed', 'stored', 'imported'
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRecord {
    pub id: String,
    pub hash_id: String,
    pub verified_at: String,
    pub result: String,  // 'match', 'mismatch'
    pub expected_hash: String,
    pub actual_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenTabRecord {
    pub id: String,
    pub session_id: String,
    pub file_path: String,
    pub tab_order: i32,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub key: String,
    pub value: String,
}

// ============================================================================
// Database Implementation
// ============================================================================

impl Database {
    /// Initialize database at the given path, creating tables if needed
    pub fn new(db_path: &PathBuf) -> SqlResult<Self> {
        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        
        let conn = Connection::open(db_path)?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }
    
    /// Create all tables if they don't exist
    fn init_schema(&self) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute_batch(r#"
            -- Sessions (open directories/workspaces)
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                root_path TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_opened_at TEXT NOT NULL
            );
            
            -- Files (discovered evidence containers)
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                path TEXT NOT NULL,
                filename TEXT NOT NULL,
                container_type TEXT NOT NULL,
                total_size INTEGER NOT NULL,
                segment_count INTEGER NOT NULL DEFAULT 1,
                discovered_at TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
                UNIQUE(session_id, path)
            );
            
            -- Hashes (computed hash records - immutable audit trail)
            CREATE TABLE IF NOT EXISTS hashes (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                hash_value TEXT NOT NULL,
                computed_at TEXT NOT NULL,
                segment_index INTEGER,
                segment_name TEXT,
                source TEXT NOT NULL DEFAULT 'computed',
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            );
            
            -- Verifications (verification audit trail)
            CREATE TABLE IF NOT EXISTS verifications (
                id TEXT PRIMARY KEY,
                hash_id TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                result TEXT NOT NULL,
                expected_hash TEXT NOT NULL,
                actual_hash TEXT NOT NULL,
                FOREIGN KEY (hash_id) REFERENCES hashes(id) ON DELETE CASCADE
            );
            
            -- Open tabs (UI state per session)
            CREATE TABLE IF NOT EXISTS open_tabs (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                tab_order INTEGER NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
                UNIQUE(session_id, file_path)
            );
            
            -- App settings (key-value store)
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            
            -- Indexes for common queries
            CREATE INDEX IF NOT EXISTS idx_files_session ON files(session_id);
            CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
            CREATE INDEX IF NOT EXISTS idx_hashes_file ON hashes(file_id);
            CREATE INDEX IF NOT EXISTS idx_hashes_algorithm ON hashes(algorithm);
            CREATE INDEX IF NOT EXISTS idx_verifications_hash ON verifications(hash_id);
            CREATE INDEX IF NOT EXISTS idx_tabs_session ON open_tabs(session_id);
        "#)?;
        
        Ok(())
    }
    
    // ========================================================================
    // Session Operations
    // ========================================================================
    
    pub fn create_session(&self, id: &str, name: &str, root_path: &str) -> SqlResult<Session> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        
        conn.execute(
            "INSERT INTO sessions (id, name, root_path, created_at, last_opened_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, name, root_path, now, now],
        )?;
        
        Ok(Session {
            id: id.to_string(),
            name: name.to_string(),
            root_path: root_path.to_string(),
            created_at: now.clone(),
            last_opened_at: now,
        })
    }
    
    pub fn get_session_by_path(&self, root_path: &str) -> SqlResult<Option<Session>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, root_path, created_at, last_opened_at FROM sessions WHERE root_path = ?1"
        )?;
        
        let mut rows = stmt.query(params![root_path])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Session {
                id: row.get(0)?,
                name: row.get(1)?,
                root_path: row.get(2)?,
                created_at: row.get(3)?,
                last_opened_at: row.get(4)?,
            }))
        } else {
            Ok(None)
        }
    }
    
    pub fn get_or_create_session(&self, root_path: &str) -> SqlResult<Session> {
        if let Some(session) = self.get_session_by_path(root_path)? {
            // Update last opened
            self.update_session_last_opened(&session.id)?;
            return Ok(session);
        }
        
        // Create new session
        let id = uuid::Uuid::new_v4().to_string();
        let name = std::path::Path::new(root_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "Untitled".to_string());
        
        self.create_session(&id, &name, root_path)
    }
    
    pub fn update_session_last_opened(&self, session_id: &str) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE sessions SET last_opened_at = ?1 WHERE id = ?2",
            params![now, session_id],
        )?;
        Ok(())
    }
    
    pub fn get_recent_sessions(&self, limit: i32) -> SqlResult<Vec<Session>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, root_path, created_at, last_opened_at 
             FROM sessions 
             ORDER BY last_opened_at DESC 
             LIMIT ?1"
        )?;
        
        let rows = stmt.query_map(params![limit], |row| {
            Ok(Session {
                id: row.get(0)?,
                name: row.get(1)?,
                root_path: row.get(2)?,
                created_at: row.get(3)?,
                last_opened_at: row.get(4)?,
            })
        })?;
        
        rows.collect()
    }
    
    pub fn get_last_session(&self) -> SqlResult<Option<Session>> {
        let sessions = self.get_recent_sessions(1)?;
        Ok(sessions.into_iter().next())
    }
    
    // ========================================================================
    // File Operations
    // ========================================================================
    
    pub fn upsert_file(&self, file: &FileRecord) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO files (id, session_id, path, filename, container_type, total_size, segment_count, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(session_id, path) DO UPDATE SET
                filename = excluded.filename,
                container_type = excluded.container_type,
                total_size = excluded.total_size,
                segment_count = excluded.segment_count",
            params![
                file.id, file.session_id, file.path, file.filename,
                file.container_type, file.total_size, file.segment_count, file.discovered_at
            ],
        )?;
        Ok(())
    }
    
    pub fn get_files_for_session(&self, session_id: &str) -> SqlResult<Vec<FileRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, path, filename, container_type, total_size, segment_count, discovered_at
             FROM files WHERE session_id = ?1 ORDER BY filename"
        )?;
        
        let rows = stmt.query_map(params![session_id], |row| {
            Ok(FileRecord {
                id: row.get(0)?,
                session_id: row.get(1)?,
                path: row.get(2)?,
                filename: row.get(3)?,
                container_type: row.get(4)?,
                total_size: row.get(5)?,
                segment_count: row.get(6)?,
                discovered_at: row.get(7)?,
            })
        })?;
        
        rows.collect()
    }
    
    pub fn get_file_by_path(&self, session_id: &str, path: &str) -> SqlResult<Option<FileRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, path, filename, container_type, total_size, segment_count, discovered_at
             FROM files WHERE session_id = ?1 AND path = ?2"
        )?;
        
        let mut rows = stmt.query(params![session_id, path])?;
        if let Some(row) = rows.next()? {
            Ok(Some(FileRecord {
                id: row.get(0)?,
                session_id: row.get(1)?,
                path: row.get(2)?,
                filename: row.get(3)?,
                container_type: row.get(4)?,
                total_size: row.get(5)?,
                segment_count: row.get(6)?,
                discovered_at: row.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }
    
    // ========================================================================
    // Hash Operations
    // ========================================================================
    
    pub fn insert_hash(&self, hash: &HashRecord) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO hashes (id, file_id, algorithm, hash_value, computed_at, segment_index, segment_name, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                hash.id, hash.file_id, hash.algorithm, hash.hash_value,
                hash.computed_at, hash.segment_index, hash.segment_name, hash.source
            ],
        )?;
        Ok(())
    }
    
    pub fn get_hashes_for_file(&self, file_id: &str) -> SqlResult<Vec<HashRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, file_id, algorithm, hash_value, computed_at, segment_index, segment_name, source
             FROM hashes WHERE file_id = ?1 ORDER BY computed_at DESC"
        )?;
        
        let rows = stmt.query_map(params![file_id], |row| {
            Ok(HashRecord {
                id: row.get(0)?,
                file_id: row.get(1)?,
                algorithm: row.get(2)?,
                hash_value: row.get(3)?,
                computed_at: row.get(4)?,
                segment_index: row.get(5)?,
                segment_name: row.get(6)?,
                source: row.get(7)?,
            })
        })?;
        
        rows.collect()
    }
    
    pub fn get_latest_hash(&self, file_id: &str, algorithm: &str, segment_index: Option<i32>) -> SqlResult<Option<HashRecord>> {
        let conn = self.conn.lock().unwrap();
        
        let sql = if segment_index.is_some() {
            "SELECT id, file_id, algorithm, hash_value, computed_at, segment_index, segment_name, source
             FROM hashes WHERE file_id = ?1 AND algorithm = ?2 AND segment_index = ?3
             ORDER BY computed_at DESC LIMIT 1"
        } else {
            "SELECT id, file_id, algorithm, hash_value, computed_at, segment_index, segment_name, source
             FROM hashes WHERE file_id = ?1 AND algorithm = ?2 AND segment_index IS NULL
             ORDER BY computed_at DESC LIMIT 1"
        };
        
        let mut stmt = conn.prepare(sql)?;
        
        let mut rows = if let Some(idx) = segment_index {
            stmt.query(params![file_id, algorithm, idx])?
        } else {
            stmt.query(params![file_id, algorithm])?
        };
        
        if let Some(row) = rows.next()? {
            Ok(Some(HashRecord {
                id: row.get(0)?,
                file_id: row.get(1)?,
                algorithm: row.get(2)?,
                hash_value: row.get(3)?,
                computed_at: row.get(4)?,
                segment_index: row.get(5)?,
                segment_name: row.get(6)?,
                source: row.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }
    
    // ========================================================================
    // Verification Operations
    // ========================================================================
    
    pub fn insert_verification(&self, verification: &VerificationRecord) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO verifications (id, hash_id, verified_at, result, expected_hash, actual_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                verification.id, verification.hash_id, verification.verified_at,
                verification.result, verification.expected_hash, verification.actual_hash
            ],
        )?;
        Ok(())
    }
    
    pub fn get_verifications_for_file(&self, file_id: &str) -> SqlResult<Vec<VerificationRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT v.id, v.hash_id, v.verified_at, v.result, v.expected_hash, v.actual_hash
             FROM verifications v
             JOIN hashes h ON v.hash_id = h.id
             WHERE h.file_id = ?1
             ORDER BY v.verified_at DESC"
        )?;
        
        let rows = stmt.query_map(params![file_id], |row| {
            Ok(VerificationRecord {
                id: row.get(0)?,
                hash_id: row.get(1)?,
                verified_at: row.get(2)?,
                result: row.get(3)?,
                expected_hash: row.get(4)?,
                actual_hash: row.get(5)?,
            })
        })?;
        
        rows.collect()
    }
    
    // ========================================================================
    // Open Tabs Operations
    // ========================================================================
    
    pub fn save_open_tabs(&self, session_id: &str, tabs: &[OpenTabRecord]) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        
        // Clear existing tabs for session
        conn.execute("DELETE FROM open_tabs WHERE session_id = ?1", params![session_id])?;
        
        // Insert new tabs
        for tab in tabs {
            conn.execute(
                "INSERT INTO open_tabs (id, session_id, file_path, tab_order, is_active)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![tab.id, session_id, tab.file_path, tab.tab_order, tab.is_active as i32],
            )?;
        }
        
        Ok(())
    }
    
    pub fn get_open_tabs(&self, session_id: &str) -> SqlResult<Vec<OpenTabRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, file_path, tab_order, is_active
             FROM open_tabs WHERE session_id = ?1 ORDER BY tab_order"
        )?;
        
        let rows = stmt.query_map(params![session_id], |row| {
            let is_active: i32 = row.get(4)?;
            Ok(OpenTabRecord {
                id: row.get(0)?,
                session_id: row.get(1)?,
                file_path: row.get(2)?,
                tab_order: row.get(3)?,
                is_active: is_active != 0,
            })
        })?;
        
        rows.collect()
    }
    
    // ========================================================================
    // Settings Operations
    // ========================================================================
    
    pub fn set_setting(&self, key: &str, value: &str) -> SqlResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
    
    pub fn get_setting(&self, key: &str) -> SqlResult<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
        
        let mut rows = stmt.query(params![key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }
}

// ============================================================================
// Global Database Instance
// ============================================================================

use std::sync::OnceLock;

static DB: OnceLock<Database> = OnceLock::new();

/// Get the global database instance, initializing if needed
pub fn get_db() -> &'static Database {
    DB.get_or_init(|| {
        let app_data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("com.ffxcheck.app");
        let db_path = app_data_dir.join("ffx.db");
        
        tracing::info!("Initializing database at: {:?}", db_path);
        
        Database::new(&db_path).expect("Failed to initialize database")
    })
}

/// Initialize database with a custom path (for testing or app-provided path)
pub fn init_db(db_path: PathBuf) -> SqlResult<()> {
    let db = Database::new(&db_path)?;
    let _ = DB.set(db);
    Ok(())
}
