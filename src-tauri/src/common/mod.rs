// Common utilities shared across forensic container parsers

pub mod hash;
pub mod binary;
pub mod segments;
pub mod io_pool;
pub mod hex;
pub mod magic;
pub mod entropy;

// Re-exports for convenience
pub use hash::{HashAlgorithm, StreamingHasher, compute_hash, hash_file_with_progress};
pub use hash::{compare_hashes, HashMatchResult, HashVerificationResult, verify_hash};
pub use binary::{read_u8, read_u16_le, read_u32_le, read_u64_le, read_u32_be};
pub use segments::{discover_numbered_segments, discover_e01_segments, get_segment_basename, is_numbered_segment};
pub use io_pool::{FileIoPool, DEFAULT_MAX_OPEN_FILES};
pub use hex::{format_hex_dump, format_hex_inline, format_hex_string, HexDumpOptions, HexDumpResult};
pub use magic::{detect_file_type, FileType, FileCategory, is_image, is_archive, is_executable};
pub use entropy::{calculate_entropy, classify_entropy, EntropyClass, EntropyResult, is_likely_encrypted};

// Shared constants - tuned for high throughput sequential I/O
// 16MB buffer provides optimal throughput for modern NVMe SSDs and HDDs
pub const BUFFER_SIZE: usize = 16 * 1024 * 1024; // 16MB buffer

// Threshold for using memory-mapped I/O (files larger than this use mmap)
pub const MMAP_THRESHOLD: u64 = 64 * 1024 * 1024; // 64MB
