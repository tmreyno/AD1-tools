//! Container abstraction layer for forensic image formats
//! 
//! This module provides a unified interface for working with various forensic
//! container formats including AD1, E01, L01, Raw, Archive, and UFED.

mod types;
mod operations;
mod scanning;
mod segments;
mod companion;

// Re-export all public types
pub use types::*;

// Re-export main operations
pub use operations::{info, info_fast, verify, extract};

// Re-export scanning functions
pub use scanning::{scan_directory, scan_directory_recursive, scan_directory_streaming};
