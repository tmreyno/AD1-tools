//! Forensic Audit Logging
//!
//! Provides structured logging for forensic chain of custody compliance.
//! All evidence file operations are logged with timestamps and context.

use std::path::Path;
use tracing::{info, warn, span, Level};

/// Log evidence file access for audit trail
pub fn log_evidence_access(
    operation: &str,
    path: &Path,
    file_type: Option<&str>,
    file_size: Option<u64>,
) {
    let _span = span!(
        Level::INFO,
        "evidence_access",
        operation = operation,
        path = %path.display(),
    ).entered();
    
    info!(
        target: "forensic_audit",
        operation = operation,
        path = %path.display(),
        file_type = file_type.unwrap_or("unknown"),
        file_size = file_size.unwrap_or(0),
        timestamp = %chrono::Utc::now().to_rfc3339(),
        "Evidence file accessed"
    );
}

/// Log evidence file hash verification
pub fn log_hash_verification(
    path: &Path,
    algorithm: &str,
    computed_hash: &str,
    expected_hash: Option<&str>,
    verified: Option<bool>,
) {
    let status = match verified {
        Some(true) => "VERIFIED",
        Some(false) => "MISMATCH",
        None => "COMPUTED",
    };
    
    info!(
        target: "forensic_audit",
        operation = "hash_verification",
        path = %path.display(),
        algorithm = algorithm,
        computed_hash = computed_hash,
        expected_hash = expected_hash.unwrap_or("none"),
        status = status,
        timestamp = %chrono::Utc::now().to_rfc3339(),
        "Hash verification completed"
    );
}

/// Log evidence container opened
pub fn log_container_opened(
    path: &Path,
    container_type: &str,
    segments: usize,
) {
    info!(
        target: "forensic_audit",
        operation = "container_open",
        path = %path.display(),
        container_type = container_type,
        segments = segments,
        timestamp = %chrono::Utc::now().to_rfc3339(),
        "Evidence container opened"
    );
}

/// Log report generation
pub fn log_report_generation(
    case_number: &str,
    format: &str,
    output_path: &Path,
) {
    info!(
        target: "forensic_audit",
        operation = "report_generation",
        case_number = case_number,
        format = format,
        output_path = %output_path.display(),
        timestamp = %chrono::Utc::now().to_rfc3339(),
        "Forensic report generated"
    );
}

/// Log security event (blocked operation, validation failure, etc.)
pub fn log_security_event(
    event_type: &str,
    description: &str,
    path: Option<&Path>,
) {
    warn!(
        target: "forensic_audit",
        event_type = "security",
        security_event = event_type,
        description = description,
        path = path.map(|p| p.display().to_string()).unwrap_or_default(),
        timestamp = %chrono::Utc::now().to_rfc3339(),
        "Security event"
    );
}

/// Log data export operation
pub fn log_data_export(
    source: &Path,
    destination: &Path,
    bytes_exported: u64,
) {
    info!(
        target: "forensic_audit",
        operation = "data_export",
        source = %source.display(),
        destination = %destination.display(),
        bytes_exported = bytes_exported,
        timestamp = %chrono::Utc::now().to_rfc3339(),
        "Evidence data exported"
    );
}

/// Audit context for tracking operations on a single evidence item
pub struct EvidenceAuditContext {
    pub evidence_id: String,
    pub path: String,
    pub opened_at: chrono::DateTime<chrono::Utc>,
}

impl EvidenceAuditContext {
    pub fn new(evidence_id: impl Into<String>, path: impl Into<String>) -> Self {
        let ctx = Self {
            evidence_id: evidence_id.into(),
            path: path.into(),
            opened_at: chrono::Utc::now(),
        };
        
        info!(
            target: "forensic_audit",
            operation = "session_start",
            evidence_id = %ctx.evidence_id,
            path = %ctx.path,
            timestamp = %ctx.opened_at.to_rfc3339(),
            "Evidence audit session started"
        );
        
        ctx
    }
    
    pub fn log_operation(&self, operation: &str, details: &str) {
        info!(
            target: "forensic_audit",
            evidence_id = %self.evidence_id,
            operation = operation,
            details = details,
            timestamp = %chrono::Utc::now().to_rfc3339(),
            "Evidence operation"
        );
    }
}

impl Drop for EvidenceAuditContext {
    fn drop(&mut self) {
        let duration = chrono::Utc::now() - self.opened_at;
        info!(
            target: "forensic_audit",
            operation = "session_end",
            evidence_id = %self.evidence_id,
            path = %self.path,
            duration_secs = duration.num_seconds(),
            timestamp = %chrono::Utc::now().to_rfc3339(),
            "Evidence audit session ended"
        );
    }
}
