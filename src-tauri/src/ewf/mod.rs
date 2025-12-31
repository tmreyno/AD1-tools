//! EWF (Expert Witness Format) - E01/EWF/Ex01 forensic image parser
//!
//! This module provides parsing, verification, and extraction capabilities for
//! EnCase's Expert Witness Format (EWF), commonly known as E01 files.
//!
//! ## EWF Format Overview
//!
//! EWF is a segmented disk image format developed by Guidance Software (now OpenText)
//! for their EnCase forensic suite. Key features:
//!
//! - **Segmented storage**: Large images split across multiple .E01, .E02, etc. files
//! - **Zlib compression**: Chunks are individually compressed for space efficiency
//! - **Chunk-based access**: Random access to any part of the image
//! - **Embedded hashes**: MD5/SHA1 verification built into the format
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │ EVF Signature (8 bytes)                                      │
//! │  - EWF1: "EVF\x09\x0d\x0a\xff\x00"                           │
//! │  - EWF2: "EVF2\x0d\x0a\x81\x00"                              │
//! ├──────────────────────────────────────────────────────────────┤
//! │ Section Chain (linked list of sections)                      │
//! │  ┌─────────────────────────────────────────────────────────┐ │
//! │  │ header: Case info, examiner, etc.                       │ │
//! │  │ volume: Chunk count, sector info, compression           │ │
//! │  │ sectors: Compressed chunk data                          │ │
//! │  │ table: Chunk offset table                               │ │
//! │  │ hash/digest: Embedded MD5/SHA1 hashes                   │ │
//! │  │ done: End of segment marker                             │ │
//! │  └─────────────────────────────────────────────────────────┘ │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Multi-Segment Support
//!
//! E01 files can span multiple segments:
//! - First segment (.E01) contains all metadata
//! - Subsequent segments (.E02, .E03, etc.) contain additional chunk data
//! - "next" sections indicate continuation to next segment
//!
//! ## Usage
//!
//! ```rust,ignore
//! use ewf::{info, verify, extract, is_e01};
//!
//! // Check if file is E01 format
//! if is_e01("/path/to/image.E01")? {
//!     // Get container info
//!     let info = info("/path/to/image.E01")?;
//!     println!("Image size: {} bytes", info.total_size);
//!     
//!     // Verify image integrity
//!     let hash = verify("/path/to/image.E01", "md5")?;
//!     
//!     // Extract to raw image
//!     extract("/path/to/image.E01", "/output/dir")?;
//! }
//! ```

mod types;
mod cache;
mod handle;
mod operations;

// Re-export public types
pub use types::{
    StoredImageHash, VolumeSection, E01Info, VerifyResult,
};

// Re-export the handle for advanced usage
pub use handle::E01Handle;

// Re-export public functions
pub use operations::{
    info, is_e01, get_segment_paths, hash_single_segment,
    verify, verify_with_progress, verify_chunks,
    extract,
};
