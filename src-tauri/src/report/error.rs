//! Error types for report generation

use std::fmt;
use std::io;

/// Result type alias for report operations
pub type ReportResult<T> = Result<T, ReportError>;

/// Errors that can occur during report generation
#[derive(Debug)]
pub enum ReportError {
    /// I/O error (file read/write)
    Io(io::Error),
    /// Template rendering error
    Template(tera::Error),
    /// PDF generation error
    Pdf(String),
    /// DOCX generation error
    Docx(String),
    /// Typst generation/compilation error
    #[cfg(feature = "typst-reports")]
    Typst(String),
    /// Serialization error
    Serialization(serde_json::Error),
    /// Unsupported output format
    UnsupportedFormat(String),
    /// AI assistant not configured
    AiNotConfigured,
    /// AI generation error
    #[cfg(feature = "ai-assistant")]
    AiError(String),
    /// Validation error
    Validation(String),
    /// Missing required field
    MissingField(String),
    /// Invalid data
    InvalidData(String),
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReportError::Io(e) => write!(f, "I/O error: {}", e),
            ReportError::Template(e) => write!(f, "Template error: {}", e),
            ReportError::Pdf(e) => write!(f, "PDF generation error: {}", e),
            ReportError::Docx(e) => write!(f, "DOCX generation error: {}", e),
            #[cfg(feature = "typst-reports")]
            ReportError::Typst(e) => write!(f, "Typst generation error: {}", e),
            ReportError::Serialization(e) => write!(f, "Serialization error: {}", e),
            ReportError::UnsupportedFormat(e) => write!(f, "Unsupported format: {}", e),
            ReportError::AiNotConfigured => write!(f, "AI assistant not configured"),
            #[cfg(feature = "ai-assistant")]
            ReportError::AiError(e) => write!(f, "AI error: {}", e),
            ReportError::Validation(e) => write!(f, "Validation error: {}", e),
            ReportError::MissingField(e) => write!(f, "Missing required field: {}", e),
            ReportError::InvalidData(e) => write!(f, "Invalid data: {}", e),
        }
    }
}

impl std::error::Error for ReportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReportError::Io(e) => Some(e),
            ReportError::Template(e) => Some(e),
            ReportError::Serialization(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ReportError {
    fn from(err: io::Error) -> Self {
        ReportError::Io(err)
    }
}

impl From<tera::Error> for ReportError {
    fn from(err: tera::Error) -> Self {
        ReportError::Template(err)
    }
}

impl From<serde_json::Error> for ReportError {
    fn from(err: serde_json::Error) -> Self {
        ReportError::Serialization(err)
    }
}
