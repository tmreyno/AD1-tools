// Common utilities shared across forensic container parsers

pub mod hash;
pub mod binary;
pub mod segments;

// Re-exports for convenience
pub use hash::{HashAlgorithm, StreamingHasher, compute_hash, hash_file_with_progress};
pub use binary::{read_u8, read_u16_le, read_u32_le, read_u64_le};
pub use segments::{discover_numbered_segments, get_segment_basename, is_numbered_segment};

// Shared constants
pub const BUFFER_SIZE: usize = 8 * 1024 * 1024; // 8MB buffer for optimal throughput
