//! AD1 (AccessData Logical Image) Parser
//!
//! This module provides parsing and verification for AccessData's AD1 logical
//! evidence container format, commonly used in FTK (Forensic Toolkit).
//!
//! ## AD1 Format Structure
//!
//! AD1 files are **segmented logical containers** with zlib-compressed content:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │ Segment Header (64 bytes)                                    │
//! │  - Signature: "ADSEGMENTEDFILE" (15 bytes)                  │
//! │  - Segment Index (u32)                                       │
//! │  - Segment Number (u32) - total segment count               │
//! │  - Fragments Size (u32)                                      │
//! │  - Header Size (u32)                                         │
//! ├──────────────────────────────────────────────────────────────┤
//! │ Logical Header (within 512 bytes after segment header)       │
//! │  - Signature "AD\0\0" (4 bytes)                             │
//! │  - Image Version (u32)                                       │
//! │  - Zlib Chunk Size (u32)                                     │
//! │  - Logical Metadata Address (u64)                            │
//! │  - First Item Address (u64)                                  │
//! │  - Data Source Name                                          │
//! ├──────────────────────────────────────────────────────────────┤
//! │ Item Chain (linked list structure)                           │
//! │  - Each item: next_addr, child_addr, metadata_addr           │
//! │  - Item type: 0x05 = folder, others = files                 │
//! │  - Zlib-compressed data at zlib_metadata_addr                │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Multi-Segment Support
//!
//! AD1 containers can span multiple files (.ad1, .ad2, .ad3, etc.):
//! - First segment contains all headers and metadata structure
//! - Subsequent segments contain additional compressed data blocks
//! - Segment number in header indicates total segment count
//!
//! ## Usage
//!
//! ```rust,ignore
//! // Get container info with file tree
//! let info = ad1::info("/path/to/evidence.ad1", true)?;
//!
//! // Fast info (headers only, no tree parsing)
//! let info_fast = ad1::info_fast("/path/to/evidence.ad1")?;
//!
//! // Verify file hashes
//! let results = ad1::verify("/path/to/evidence.ad1", "sha1")?;
//!
//! // Extract to output directory
//! ad1::extract("/path/to/evidence.ad1", "/output/dir")?;
//! ```

mod types;
mod parser;
mod operations;
mod utils;

// Re-export public types
#[allow(unused_imports)]
pub use types::{
    Ad1Info, SegmentHeaderInfo, LogicalHeaderInfo, 
    TreeEntry, VerifyEntry,
};

// Re-export public functions
#[allow(unused_imports)]
pub use operations::{
    info, info_fast, verify, verify_with_progress,
    extract, extract_with_progress, is_ad1,
};
