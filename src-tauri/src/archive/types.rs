//! Archive type definitions
//!
//! Contains shared types for archive format detection and metadata extraction.
//!
//! ## Archive vs Forensic Container Formats
//!
//! | Aspect | Archives | Forensic Containers |
//! |--------|----------|---------------------|
//! | Purpose | Compression/bundling | Evidence preservation |
//! | Integrity | CRC32 (error detection) | Cryptographic hashes |
//! | Metadata | Basic (name, size, date) | Rich (case, examiner, notes) |
//! | Chain of Custody | No | Yes |
//! | Examples | ZIP, 7z, RAR | E01, AD1, AFF |

use serde::Serialize;

/// Archive format type
///
/// Note: This enum includes both true archives (compression-focused) and
/// disk image formats (VM, forensic) that share detection patterns.
/// True forensic containers (E01, AD1, L01) are handled by dedicated modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ArchiveFormat {
    // =========================================================================
    // Compression Formats
    // =========================================================================
    SevenZip,
    Zip,
    Zip64,
    Rar4,
    Rar5,
    Gzip,
    Tar,
    TarGz,
    Xz,
    Bzip2,
    Lz4,
    Zstd,
    
    // =========================================================================
    // Forensic Archive Formats (not full forensic containers)
    // =========================================================================
    /// Advanced Forensic Format (open source)
    Aff,
    /// AFF4 - Modern AFF using ZIP container
    Aff4,
    /// SMART format (.s01) - ASR Data SMART
    Smart,
    
    // =========================================================================
    // Optical Disc Formats
    // =========================================================================
    /// ISO 9660 - CD/DVD disc image
    Iso,
    
    // =========================================================================
    // Virtual Machine Disk Formats
    // =========================================================================
    /// VMware Virtual Disk
    Vmdk,
    /// Microsoft Virtual Hard Disk (legacy)
    Vhd,
    /// Microsoft Virtual Hard Disk (modern)
    Vhdx,
    /// QEMU Copy-On-Write v2
    Qcow2,
    /// VirtualBox Virtual Disk Image
    Vdi,
    
    // =========================================================================
    // macOS Formats
    // =========================================================================
    /// Apple Disk Image
    Dmg,
}

impl std::fmt::Display for ArchiveFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Compression
            ArchiveFormat::SevenZip => write!(f, "7-Zip"),
            ArchiveFormat::Zip => write!(f, "ZIP"),
            ArchiveFormat::Zip64 => write!(f, "ZIP64"),
            ArchiveFormat::Rar4 => write!(f, "RAR4"),
            ArchiveFormat::Rar5 => write!(f, "RAR5"),
            ArchiveFormat::Gzip => write!(f, "GZIP"),
            ArchiveFormat::Tar => write!(f, "TAR"),
            ArchiveFormat::TarGz => write!(f, "TAR.GZ"),
            ArchiveFormat::Xz => write!(f, "XZ"),
            ArchiveFormat::Bzip2 => write!(f, "BZIP2"),
            ArchiveFormat::Lz4 => write!(f, "LZ4"),
            ArchiveFormat::Zstd => write!(f, "ZSTD"),
            // Forensic archives
            ArchiveFormat::Aff => write!(f, "AFF"),
            ArchiveFormat::Aff4 => write!(f, "AFF4"),
            ArchiveFormat::Smart => write!(f, "SMART"),
            // Optical disc
            ArchiveFormat::Iso => write!(f, "ISO 9660"),
            // Virtual machine
            ArchiveFormat::Vmdk => write!(f, "VMDK"),
            ArchiveFormat::Vhd => write!(f, "VHD"),
            ArchiveFormat::Vhdx => write!(f, "VHDX"),
            ArchiveFormat::Qcow2 => write!(f, "QCOW2"),
            ArchiveFormat::Vdi => write!(f, "VDI"),
            // macOS
            ArchiveFormat::Dmg => write!(f, "DMG"),
        }
    }
}

/// Archive information
#[derive(Debug, Clone, Serialize)]
pub struct ArchiveInfo {
    pub format: String,
    pub segment_count: u32,
    pub total_size: u64,
    pub segment_names: Vec<String>,
    pub segment_sizes: Vec<u64>,
    pub first_segment: String,
    pub last_segment: String,
    pub is_multipart: bool,
    /// Number of entries in the archive (from Central Directory for ZIP)
    pub entry_count: Option<u32>,
    /// Whether archive has encrypted headers (filenames hidden)
    pub encrypted_headers: bool,
    /// Whether archive uses AES encryption
    pub aes_encrypted: bool,
    /// ZIP-specific: Central Directory offset
    pub central_dir_offset: Option<u64>,
    /// ZIP-specific: Central Directory size
    pub central_dir_size: Option<u32>,
    /// 7z-specific: Next header offset (absolute, from file start)
    pub next_header_offset: Option<u64>,
    /// 7z-specific: Next header size
    pub next_header_size: Option<u64>,
    /// 7z-specific: Archive version (major.minor)
    pub version: Option<String>,
    /// 7z-specific: Start Header CRC valid
    pub start_header_crc_valid: Option<bool>,
    /// 7z-specific: Next Header CRC (for reference)
    pub next_header_crc: Option<u32>,
    /// UFED extraction detected (UFDR/UFDX/UFD)
    pub ufed_detected: bool,
    /// UFED file paths found inside archive
    pub ufed_files: Vec<String>,
}

impl Default for ArchiveInfo {
    fn default() -> Self {
        Self {
            format: String::new(),
            segment_count: 0,
            total_size: 0,
            segment_names: Vec::new(),
            segment_sizes: Vec::new(),
            first_segment: String::new(),
            last_segment: String::new(),
            is_multipart: false,
            entry_count: None,
            encrypted_headers: false,
            aes_encrypted: false,
            central_dir_offset: None,
            central_dir_size: None,
            next_header_offset: None,
            next_header_size: None,
            version: None,
            start_header_crc_valid: None,
            next_header_crc: None,
            ufed_detected: false,
            ufed_files: Vec::new(),
        }
    }
}
