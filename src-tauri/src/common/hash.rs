// Shared hash utilities for forensic container verification
//
// Provides unified hashing across all container formats (AD1, E01, RAW, L01)
// with support for MD5, SHA-1, SHA-256, SHA-512, BLAKE2b, BLAKE3

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use sha1::{Sha1, Digest};
use sha2::{Sha256, Sha512};
use blake2::Blake2b512;
use blake3::Hasher as Blake3Hasher;

use super::BUFFER_SIZE;

// =============================================================================
// Hash Algorithm Enum
// =============================================================================

/// Supported hash algorithms for forensic verification
/// - MD5/SHA1: Legacy algorithms for AD1 metadata comparison
/// - SHA256/SHA512: NIST approved, court-accepted forensic standards
/// - BLAKE3: Modern, extremely fast cryptographic hash
/// - BLAKE2b: Fast cryptographic hash (used in many security applications)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Blake3,
    Blake2,
}

impl HashAlgorithm {
    /// Parse algorithm name from string (case-insensitive)
    pub fn from_str(algorithm: &str) -> Result<Self, String> {
        match algorithm.trim().to_lowercase().as_str() {
            "md5" => Ok(HashAlgorithm::Md5),
            "sha1" | "sha-1" => Ok(HashAlgorithm::Sha1),
            "sha256" | "sha-256" => Ok(HashAlgorithm::Sha256),
            "sha512" | "sha-512" => Ok(HashAlgorithm::Sha512),
            "blake3" => Ok(HashAlgorithm::Blake3),
            "blake2" | "blake2b" => Ok(HashAlgorithm::Blake2),
            _ => Err(format!(
                "Unsupported hash algorithm: '{}'. Supported: md5, sha1, sha256, sha512, blake3, blake2",
                algorithm
            )),
        }
    }

    /// Get the canonical algorithm name
    pub fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Md5 => "MD5",
            HashAlgorithm::Sha1 => "SHA-1",
            HashAlgorithm::Sha256 => "SHA-256",
            HashAlgorithm::Sha512 => "SHA-512",
            HashAlgorithm::Blake3 => "BLAKE3",
            HashAlgorithm::Blake2 => "BLAKE2b",
        }
    }

    /// Get expected hash length in hex characters
    pub fn hash_length(&self) -> usize {
        match self {
            HashAlgorithm::Md5 => 32,
            HashAlgorithm::Sha1 => 40,
            HashAlgorithm::Sha256 => 64,
            HashAlgorithm::Sha512 => 128,
            HashAlgorithm::Blake3 => 64,
            HashAlgorithm::Blake2 => 128,
        }
    }
}

/// Convenience function to parse algorithm string
pub fn parse_algorithm(algorithm: &str) -> Result<HashAlgorithm, String> {
    HashAlgorithm::from_str(algorithm)
}

// =============================================================================
// Streaming Hasher - Unified interface for incremental hashing
// =============================================================================

/// A unified streaming hasher that supports all hash algorithms
/// Used for incremental hashing of large files or chunks
pub enum StreamingHasher {
    Md5(md5::Context),
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Sha512),
    Blake3(Blake3Hasher),
    Blake2(Blake2b512),
}

impl StreamingHasher {
    /// Create a new streaming hasher for the specified algorithm
    pub fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Md5 => StreamingHasher::Md5(md5::Context::new()),
            HashAlgorithm::Sha1 => StreamingHasher::Sha1(Sha1::new()),
            HashAlgorithm::Sha256 => StreamingHasher::Sha256(Sha256::new()),
            HashAlgorithm::Sha512 => StreamingHasher::Sha512(Sha512::new()),
            HashAlgorithm::Blake3 => StreamingHasher::Blake3(Blake3Hasher::new()),
            HashAlgorithm::Blake2 => StreamingHasher::Blake2(Blake2b512::new()),
        }
    }

    /// Create from algorithm string
    pub fn from_str(algorithm: &str) -> Result<Self, String> {
        Ok(Self::new(HashAlgorithm::from_str(algorithm)?))
    }

    /// Update the hash with more data
    pub fn update(&mut self, data: &[u8]) {
        match self {
            StreamingHasher::Md5(h) => h.consume(data),
            StreamingHasher::Sha1(h) => h.update(data),
            StreamingHasher::Sha256(h) => h.update(data),
            StreamingHasher::Sha512(h) => h.update(data),
            StreamingHasher::Blake3(h) => { h.update(data); }
            StreamingHasher::Blake2(h) => h.update(data),
        }
    }

    /// Update with parallel hashing (only effective for BLAKE3)
    /// Falls back to regular update for other algorithms
    pub fn update_parallel(&mut self, data: &[u8]) {
        match self {
            StreamingHasher::Blake3(h) => { h.update_rayon(data); }
            _ => self.update(data),
        }
    }

    /// Finalize and return the hash as a hex string
    pub fn finalize(self) -> String {
        match self {
            StreamingHasher::Md5(h) => format!("{:x}", h.compute()),
            StreamingHasher::Sha1(h) => hex::encode(h.finalize()),
            StreamingHasher::Sha256(h) => hex::encode(h.finalize()),
            StreamingHasher::Sha512(h) => hex::encode(h.finalize()),
            StreamingHasher::Blake3(h) => h.finalize().to_hex().to_string(),
            StreamingHasher::Blake2(h) => hex::encode(h.finalize()),
        }
    }
}

// =============================================================================
// One-shot Hash Computation
// =============================================================================

/// Compute hash of data using specified algorithm (one-shot, for small data)
pub fn compute_hash(data: &[u8], algorithm: HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Md5 => format!("{:x}", md5::compute(data)),
        HashAlgorithm::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Blake3 => {
            let mut hasher = Blake3Hasher::new();
            hasher.update(data);
            hasher.finalize().to_hex().to_string()
        }
        HashAlgorithm::Blake2 => {
            let mut hasher = Blake2b512::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
    }
}

/// Compute hash from algorithm string (convenience wrapper)
pub fn compute_hash_str(data: &[u8], algorithm: &str) -> Result<String, String> {
    let algo = HashAlgorithm::from_str(algorithm)?;
    Ok(compute_hash(data, algo))
}

// =============================================================================
// File Hashing with Progress
// =============================================================================

/// Hash a file with progress reporting
/// 
/// # Arguments
/// * `path` - Path to the file to hash
/// * `algorithm` - Hash algorithm to use
/// * `progress_callback` - Called with (bytes_processed, total_bytes)
/// 
/// # Returns
/// The hex-encoded hash string
pub fn hash_file_with_progress<F>(
    path: &Path,
    algorithm: &str,
    mut progress_callback: F,
) -> Result<String, String>
where
    F: FnMut(u64, u64),
{
    if !path.exists() {
        return Err(format!("File not found: {}", path.display()));
    }

    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;
    let total_size = metadata.len();

    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);

    let algorithm_lower = algorithm.to_lowercase();

    // For BLAKE3, use parallel hashing for best performance
    if algorithm_lower == "blake3" {
        return hash_file_blake3_parallel(&mut reader, total_size, &mut progress_callback);
    }

    // For other algorithms, use streaming hasher
    let mut hasher = StreamingHasher::from_str(algorithm)?;
    let mut bytes_read_total = 0u64;
    let report_interval = (total_size / 20).max(BUFFER_SIZE as u64);
    let mut last_report = 0u64;

    loop {
        let buf = reader.fill_buf()
            .map_err(|e| format!("Read error: {}", e))?;
        let len = buf.len();
        if len == 0 {
            break;
        }

        hasher.update(buf);
        reader.consume(len);

        bytes_read_total += len as u64;
        if bytes_read_total - last_report >= report_interval {
            progress_callback(bytes_read_total, total_size);
            last_report = bytes_read_total;
        }
    }

    progress_callback(total_size, total_size);
    Ok(hasher.finalize())
}

/// BLAKE3 optimized path using rayon parallel hashing
fn hash_file_blake3_parallel<R, F>(
    reader: &mut BufReader<R>,
    total_size: u64,
    progress_callback: &mut F,
) -> Result<String, String>
where
    R: std::io::Read,
    F: FnMut(u64, u64),
{
    let mut hasher = Blake3Hasher::new();
    let mut bytes_read_total = 0u64;
    let report_interval = (total_size / 20).max(BUFFER_SIZE as u64);
    let mut last_report = 0u64;

    loop {
        let buf = reader.fill_buf()
            .map_err(|e| format!("Read error: {}", e))?;
        let len = buf.len();
        if len == 0 {
            break;
        }

        // BLAKE3 update_rayon uses all cores for parallel hashing
        hasher.update_rayon(buf);
        reader.consume(len);

        bytes_read_total += len as u64;
        if bytes_read_total - last_report >= report_interval {
            progress_callback(bytes_read_total, total_size);
            last_report = bytes_read_total;
        }
    }

    progress_callback(total_size, total_size);
    Ok(hasher.finalize().to_hex().to_string())
}

/// Hash a file without progress reporting (convenience wrapper)
pub fn hash_file(path: &Path, algorithm: &str) -> Result<String, String> {
    hash_file_with_progress(path, algorithm, |_, _| {})
}

// =============================================================================
// Hash Validation Utilities
// =============================================================================

/// Validate that a string looks like a valid hash for the given algorithm
pub fn is_valid_hash(hash: &str, algorithm: HashAlgorithm) -> bool {
    let expected_len = algorithm.hash_length();
    hash.len() == expected_len && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Guess the hash algorithm from a hash string based on length
pub fn guess_algorithm_from_hash(hash: &str) -> Option<HashAlgorithm> {
    match hash.len() {
        32 => Some(HashAlgorithm::Md5),
        40 => Some(HashAlgorithm::Sha1),
        64 => Some(HashAlgorithm::Sha256), // Could also be BLAKE3
        128 => Some(HashAlgorithm::Sha512), // Could also be BLAKE2b
        _ => None,
    }
}

/// Compare two hashes (case-insensitive)
pub fn hashes_match(hash1: &str, hash2: &str) -> bool {
    hash1.to_lowercase() == hash2.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_parsing() {
        assert_eq!(HashAlgorithm::from_str("md5").unwrap(), HashAlgorithm::Md5);
        assert_eq!(HashAlgorithm::from_str("MD5").unwrap(), HashAlgorithm::Md5);
        assert_eq!(HashAlgorithm::from_str("sha1").unwrap(), HashAlgorithm::Sha1);
        assert_eq!(HashAlgorithm::from_str("SHA-1").unwrap(), HashAlgorithm::Sha1);
        assert_eq!(HashAlgorithm::from_str("sha256").unwrap(), HashAlgorithm::Sha256);
        assert_eq!(HashAlgorithm::from_str("SHA-256").unwrap(), HashAlgorithm::Sha256);
        assert_eq!(HashAlgorithm::from_str("blake3").unwrap(), HashAlgorithm::Blake3);
        assert!(HashAlgorithm::from_str("invalid").is_err());
    }

    #[test]
    fn test_compute_hash() {
        let data = b"hello world";
        
        let md5 = compute_hash(data, HashAlgorithm::Md5);
        assert_eq!(md5, "5eb63bbbe01eeed093cb22bb8f5acdc3");
        
        let sha1 = compute_hash(data, HashAlgorithm::Sha1);
        assert_eq!(sha1, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
    }

    #[test]
    fn test_streaming_hasher() {
        let mut hasher = StreamingHasher::new(HashAlgorithm::Md5);
        hasher.update(b"hello ");
        hasher.update(b"world");
        let hash = hasher.finalize();
        assert_eq!(hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn test_hash_validation() {
        assert!(is_valid_hash("5eb63bbbe01eeed093cb22bb8f5acdc3", HashAlgorithm::Md5));
        assert!(!is_valid_hash("invalid", HashAlgorithm::Md5));
        assert!(!is_valid_hash("5eb63bbbe01eeed093cb22bb8f5acdc3", HashAlgorithm::Sha1));
    }

    #[test]
    fn test_guess_algorithm() {
        assert_eq!(guess_algorithm_from_hash("5eb63bbbe01eeed093cb22bb8f5acdc3"), Some(HashAlgorithm::Md5));
        assert_eq!(guess_algorithm_from_hash("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"), Some(HashAlgorithm::Sha1));
    }
}
