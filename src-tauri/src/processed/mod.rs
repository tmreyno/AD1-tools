//! Processed Database Support
//!
//! This module handles detection and parsing of processed forensic databases
//! from tools like Magnet AXIOM, Cellebrite Physical Analyzer, X-Ways, etc.
//!
//! These are DISTINCT from raw evidence containers (E01, AD1, L01) - they contain
//! parsed/processed results from forensic examinations.

pub mod types;
pub mod detection;
pub mod axiom;
pub mod commands;

pub use types::*;
pub use detection::*;
pub use commands::*;
