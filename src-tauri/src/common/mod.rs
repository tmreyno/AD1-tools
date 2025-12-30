// Common utilities shared across forensic container parsers

pub mod hash;
pub mod binary;
pub mod segments;
pub mod io_pool;

// Re-exports for convenience
pub use hash::{HashAlgorithm, StreamingHasher, compute_hash, hash_file_with_progress};
pub use binary::{read_u8, read_u16_le, read_u32_le, read_u64_le, read_u32_be};
pub use segments::{discover_numbered_segments, discover_e01_segments, get_segment_basename, is_numbered_segment};
pub use io_pool::{FileIoPool, DEFAULT_MAX_OPEN_FILES};

// Shared constants - tuned for high throughput sequential I/O
// 16MB buffer provides optimal throughput for modern NVMe SSDs and HDDs
pub const BUFFER_SIZE: usize = 16 * 1024 * 1024; // 16MB buffer

// Threshold for using memory-mapped I/O (files larger than this use mmap)
pub const MMAP_THRESHOLD: u64 = 64 * 1024 * 1024; // 64MB
