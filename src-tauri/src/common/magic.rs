//! File type detection via magic signatures
//!
//! Detects file types from header bytes without relying on extensions.
//! Essential for forensic analysis where file extensions may be incorrect or missing.

use serde::Serialize;

// =============================================================================
// File Type Structures
// =============================================================================

/// Detected file type information
#[derive(Debug, Clone, Serialize)]
pub struct FileType {
    /// MIME type (e.g., "application/pdf")
    pub mime: String,
    /// Human-readable description
    pub description: String,
    /// Common file extension(s)
    pub extensions: Vec<String>,
    /// Category for grouping
    pub category: FileCategory,
    /// Confidence level of detection
    pub confidence: Confidence,
}

/// File type categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FileCategory {
    /// Images (JPEG, PNG, GIF, etc.)
    Image,
    /// Documents (PDF, Office, etc.)
    Document,
    /// Archives (ZIP, RAR, 7z, etc.)
    Archive,
    /// Executables (EXE, ELF, Mach-O, etc.)
    Executable,
    /// Audio files
    Audio,
    /// Video files
    Video,
    /// Database files
    Database,
    /// Forensic containers (E01, AD1, etc.)
    Forensic,
    /// System/configuration files
    System,
    /// Text-based files
    Text,
    /// Unknown/unrecognized
    Unknown,
}

/// Detection confidence level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Confidence {
    /// Strong magic signature match
    High,
    /// Partial or common signature
    Medium,
    /// Heuristic/guess based on patterns
    Low,
}

impl FileType {
    fn new(mime: &str, description: &str, extensions: &[&str], category: FileCategory) -> Self {
        Self {
            mime: mime.to_string(),
            description: description.to_string(),
            extensions: extensions.iter().map(|s| s.to_string()).collect(),
            category,
            confidence: Confidence::High,
        }
    }

    fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }
}

// =============================================================================
// Magic Detection
// =============================================================================

/// Detect file type from header bytes
///
/// Requires at least 32 bytes for reliable detection, but can work with less.
/// Returns None if file type cannot be determined.
pub fn detect_file_type(header: &[u8]) -> Option<FileType> {
    if header.is_empty() {
        return None;
    }

    // =========================================================================
    // Images
    // =========================================================================
    
    // JPEG: FF D8 FF
    if header.len() >= 3 && header[..3] == [0xFF, 0xD8, 0xFF] {
        return Some(FileType::new(
            "image/jpeg", "JPEG Image", &["jpg", "jpeg"], FileCategory::Image
        ));
    }
    
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if header.len() >= 8 && header[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some(FileType::new(
            "image/png", "PNG Image", &["png"], FileCategory::Image
        ));
    }
    
    // GIF: GIF87a or GIF89a
    if header.len() >= 6 && (header[..6] == *b"GIF87a" || header[..6] == *b"GIF89a") {
        return Some(FileType::new(
            "image/gif", "GIF Image", &["gif"], FileCategory::Image
        ));
    }
    
    // WebP: RIFF....WEBP
    if header.len() >= 12 && header[..4] == *b"RIFF" && header[8..12] == *b"WEBP" {
        return Some(FileType::new(
            "image/webp", "WebP Image", &["webp"], FileCategory::Image
        ));
    }
    
    // BMP: BM
    if header.len() >= 2 && header[..2] == *b"BM" {
        return Some(FileType::new(
            "image/bmp", "BMP Image", &["bmp"], FileCategory::Image
        ));
    }
    
    // TIFF: 49 49 2A 00 (little-endian) or 4D 4D 00 2A (big-endian)
    if header.len() >= 4 && (header[..4] == [0x49, 0x49, 0x2A, 0x00] || header[..4] == [0x4D, 0x4D, 0x00, 0x2A]) {
        return Some(FileType::new(
            "image/tiff", "TIFF Image", &["tif", "tiff"], FileCategory::Image
        ));
    }
    
    // ICO: 00 00 01 00
    if header.len() >= 4 && header[..4] == [0x00, 0x00, 0x01, 0x00] {
        return Some(FileType::new(
            "image/x-icon", "ICO Icon", &["ico"], FileCategory::Image
        ));
    }
    
    // HEIC/HEIF: ftyp followed by heic, heix, hevc, etc.
    if header.len() >= 12 && header[4..8] == *b"ftyp" {
        let brand = &header[8..12];
        if brand == b"heic" || brand == b"heix" || brand == b"hevc" || brand == b"mif1" {
            return Some(FileType::new(
                "image/heic", "HEIC Image", &["heic", "heif"], FileCategory::Image
            ));
        }
    }

    // =========================================================================
    // Documents
    // =========================================================================
    
    // PDF: %PDF
    if header.len() >= 4 && header[..4] == *b"%PDF" {
        return Some(FileType::new(
            "application/pdf", "PDF Document", &["pdf"], FileCategory::Document
        ));
    }
    
    // Office Open XML (docx, xlsx, pptx) - ZIP-based, check for specific entries later
    // For now, just mark as potential Office document if ZIP with PK signature
    
    // RTF: {\rtf
    if header.len() >= 5 && header[..5] == *b"{\\rtf" {
        return Some(FileType::new(
            "application/rtf", "RTF Document", &["rtf"], FileCategory::Document
        ));
    }
    
    // Microsoft Compound Document (OLE): D0 CF 11 E0 A1 B1 1A E1
    if header.len() >= 8 && header[..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        return Some(FileType::new(
            "application/x-ole-storage", "Microsoft Office Document (OLE)", 
            &["doc", "xls", "ppt", "msg"], FileCategory::Document
        ));
    }

    // =========================================================================
    // Archives
    // =========================================================================
    
    // ZIP: PK\x03\x04
    if header.len() >= 4 && header[..4] == [0x50, 0x4B, 0x03, 0x04] {
        return Some(FileType::new(
            "application/zip", "ZIP Archive", &["zip", "docx", "xlsx", "pptx", "jar", "apk"], 
            FileCategory::Archive
        ));
    }
    
    // 7-Zip: 37 7A BC AF 27 1C
    if header.len() >= 6 && header[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return Some(FileType::new(
            "application/x-7z-compressed", "7-Zip Archive", &["7z"], FileCategory::Archive
        ));
    }
    
    // RAR5: Rar!\x1a\x07\x01\x00
    if header.len() >= 8 && header[..8] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00] {
        return Some(FileType::new(
            "application/x-rar-compressed", "RAR Archive (v5)", &["rar"], FileCategory::Archive
        ));
    }
    
    // RAR4: Rar!\x1a\x07\x00
    if header.len() >= 7 && header[..7] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00] {
        return Some(FileType::new(
            "application/x-rar-compressed", "RAR Archive (v4)", &["rar"], FileCategory::Archive
        ));
    }
    
    // GZIP: 1F 8B
    if header.len() >= 2 && header[..2] == [0x1F, 0x8B] {
        return Some(FileType::new(
            "application/gzip", "GZIP Compressed", &["gz", "tgz"], FileCategory::Archive
        ));
    }
    
    // XZ: FD 37 7A 58 5A 00
    if header.len() >= 6 && header[..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
        return Some(FileType::new(
            "application/x-xz", "XZ Compressed", &["xz", "txz"], FileCategory::Archive
        ));
    }
    
    // BZIP2: BZh
    if header.len() >= 3 && header[..2] == [0x42, 0x5A] && header[2] == 0x68 {
        return Some(FileType::new(
            "application/x-bzip2", "BZIP2 Compressed", &["bz2", "tbz2"], FileCategory::Archive
        ));
    }
    
    // ZSTD: 28 B5 2F FD
    if header.len() >= 4 && header[..4] == [0x28, 0xB5, 0x2F, 0xFD] {
        return Some(FileType::new(
            "application/zstd", "Zstandard Compressed", &["zst", "zstd"], FileCategory::Archive
        ));
    }
    
    // LZ4: 04 22 4D 18
    if header.len() >= 4 && header[..4] == [0x04, 0x22, 0x4D, 0x18] {
        return Some(FileType::new(
            "application/x-lz4", "LZ4 Compressed", &["lz4"], FileCategory::Archive
        ));
    }

    // =========================================================================
    // Executables
    // =========================================================================
    
    // Windows PE: MZ
    if header.len() >= 2 && header[..2] == *b"MZ" {
        return Some(FileType::new(
            "application/x-dosexec", "Windows Executable", &["exe", "dll", "sys"], 
            FileCategory::Executable
        ));
    }
    
    // ELF: 7F ELF
    if header.len() >= 4 && header[..4] == [0x7F, 0x45, 0x4C, 0x46] {
        return Some(FileType::new(
            "application/x-executable", "ELF Executable", &["elf", "so", "o"], 
            FileCategory::Executable
        ));
    }
    
    // Mach-O: Various magic numbers
    if header.len() >= 4 {
        let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        if magic == 0xFEEDFACE || magic == 0xFEEDFACF || magic == 0xCAFEBABE {
            return Some(FileType::new(
                "application/x-mach-binary", "Mach-O Executable", &["app", "dylib"], 
                FileCategory::Executable
            ));
        }
    }

    // =========================================================================
    // Audio
    // =========================================================================
    
    // MP3: ID3 or FF FB/FA/F3/F2
    if header.len() >= 3 && header[..3] == *b"ID3" {
        return Some(FileType::new(
            "audio/mpeg", "MP3 Audio", &["mp3"], FileCategory::Audio
        ));
    }
    if header.len() >= 2 && header[0] == 0xFF && (header[1] & 0xE0) == 0xE0 {
        return Some(FileType::new(
            "audio/mpeg", "MP3 Audio", &["mp3"], FileCategory::Audio
        ).with_confidence(Confidence::Medium));
    }
    
    // WAV: RIFF....WAVE
    if header.len() >= 12 && header[..4] == *b"RIFF" && header[8..12] == *b"WAVE" {
        return Some(FileType::new(
            "audio/wav", "WAV Audio", &["wav"], FileCategory::Audio
        ));
    }
    
    // FLAC: fLaC
    if header.len() >= 4 && header[..4] == *b"fLaC" {
        return Some(FileType::new(
            "audio/flac", "FLAC Audio", &["flac"], FileCategory::Audio
        ));
    }
    
    // OGG: OggS
    if header.len() >= 4 && header[..4] == *b"OggS" {
        return Some(FileType::new(
            "audio/ogg", "OGG Audio/Video", &["ogg", "ogv", "oga"], FileCategory::Audio
        ));
    }

    // =========================================================================
    // Video
    // =========================================================================
    
    // MP4/M4V/MOV: ftyp
    if header.len() >= 12 && header[4..8] == *b"ftyp" {
        let brand = &header[8..12];
        if brand == b"isom" || brand == b"iso2" || brand == b"mp41" || brand == b"mp42" {
            return Some(FileType::new(
                "video/mp4", "MP4 Video", &["mp4", "m4v"], FileCategory::Video
            ));
        }
        if brand == b"qt  " {
            return Some(FileType::new(
                "video/quicktime", "QuickTime Video", &["mov"], FileCategory::Video
            ));
        }
    }
    
    // AVI: RIFF....AVI
    if header.len() >= 12 && header[..4] == *b"RIFF" && header[8..12] == *b"AVI " {
        return Some(FileType::new(
            "video/avi", "AVI Video", &["avi"], FileCategory::Video
        ));
    }
    
    // MKV/WebM: 1A 45 DF A3 (EBML)
    if header.len() >= 4 && header[..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        return Some(FileType::new(
            "video/x-matroska", "Matroska Video", &["mkv", "webm"], FileCategory::Video
        ));
    }
    
    // FLV: FLV
    if header.len() >= 3 && header[..3] == *b"FLV" {
        return Some(FileType::new(
            "video/x-flv", "Flash Video", &["flv"], FileCategory::Video
        ));
    }

    // =========================================================================
    // Forensic Containers
    // =========================================================================
    
    // E01/EnCase: EVF\x09\x0d\x0a\xff\x00
    if header.len() >= 8 && header[..8] == [0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00] {
        return Some(FileType::new(
            "application/x-ewf", "EnCase Evidence File", &["e01"], FileCategory::Forensic
        ));
    }
    
    // AD1: ADSEGMENTEDFILE
    if header.len() >= 16 && header[..16] == *b"ADSEGMENTEDFILE\x00" {
        return Some(FileType::new(
            "application/x-ad1", "AccessData AD1 Image", &["ad1"], FileCategory::Forensic
        ));
    }
    
    // L01: LVF\x09\x0d\x0a\xff\x00
    if header.len() >= 8 && header[..8] == [0x4C, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00] {
        return Some(FileType::new(
            "application/x-l01", "EnCase Logical Evidence", &["l01"], FileCategory::Forensic
        ));
    }
    
    // AFF: AFF
    if header.len() >= 3 && header[..3] == *b"AFF" {
        return Some(FileType::new(
            "application/x-aff", "Advanced Forensic Format", &["aff"], FileCategory::Forensic
        ));
    }

    // =========================================================================
    // Database
    // =========================================================================
    
    // SQLite: SQLite format 3\x00
    if header.len() >= 16 && header[..16] == *b"SQLite format 3\x00" {
        return Some(FileType::new(
            "application/x-sqlite3", "SQLite Database", &["db", "sqlite", "sqlite3"], 
            FileCategory::Database
        ));
    }

    // =========================================================================
    // System Files
    // =========================================================================
    
    // Windows Registry: regf
    if header.len() >= 4 && header[..4] == *b"regf" {
        return Some(FileType::new(
            "application/x-ms-registry", "Windows Registry Hive", &["dat"], 
            FileCategory::System
        ));
    }
    
    // Windows Prefetch: Various signatures
    if header.len() >= 8 {
        // MAM\x04 (compressed prefetch Win8+)
        if header[..4] == [0x4D, 0x41, 0x4D, 0x04] {
            return Some(FileType::new(
                "application/x-prefetch", "Windows Prefetch (Compressed)", &["pf"], 
                FileCategory::System
            ));
        }
        // SCCA signature in older prefetch
        if header[4..8] == *b"SCCA" {
            return Some(FileType::new(
                "application/x-prefetch", "Windows Prefetch", &["pf"], 
                FileCategory::System
            ));
        }
    }

    // =========================================================================
    // Text-based (low confidence heuristics)
    // =========================================================================
    
    // XML: <?xml
    if header.len() >= 5 && header[..5] == *b"<?xml" {
        return Some(FileType::new(
            "application/xml", "XML Document", &["xml"], FileCategory::Text
        ));
    }
    
    // HTML: <!DOCTYPE html or <html
    if header.len() >= 15 {
        let start = String::from_utf8_lossy(&header[..header.len().min(100)]).to_lowercase();
        if start.contains("<!doctype html") || start.starts_with("<html") {
            return Some(FileType::new(
                "text/html", "HTML Document", &["html", "htm"], FileCategory::Text
            ).with_confidence(Confidence::Medium));
        }
    }
    
    // JSON: starts with { or [
    if header.len() >= 1 && (header[0] == b'{' || header[0] == b'[') {
        // Very low confidence - could be many things
        return Some(FileType::new(
            "application/json", "JSON Data", &["json"], FileCategory::Text
        ).with_confidence(Confidence::Low));
    }

    None
}

/// Quick check if data looks like a specific type
pub fn is_type(header: &[u8], category: FileCategory) -> bool {
    detect_file_type(header)
        .map(|ft| ft.category == category)
        .unwrap_or(false)
}

/// Check if header indicates an image file
pub fn is_image(header: &[u8]) -> bool {
    is_type(header, FileCategory::Image)
}

/// Check if header indicates an archive
pub fn is_archive(header: &[u8]) -> bool {
    is_type(header, FileCategory::Archive)
}

/// Check if header indicates an executable
pub fn is_executable(header: &[u8]) -> bool {
    is_type(header, FileCategory::Executable)
}

/// Check if header indicates a forensic container
pub fn is_forensic_container(header: &[u8]) -> bool {
    is_type(header, FileCategory::Forensic)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_jpeg() {
        let header = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let ft = detect_file_type(&header).unwrap();
        assert_eq!(ft.mime, "image/jpeg");
        assert_eq!(ft.category, FileCategory::Image);
    }

    #[test]
    fn test_detect_png() {
        let header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let ft = detect_file_type(&header).unwrap();
        assert_eq!(ft.mime, "image/png");
    }

    #[test]
    fn test_detect_pdf() {
        let header = b"%PDF-1.4";
        let ft = detect_file_type(header).unwrap();
        assert_eq!(ft.mime, "application/pdf");
        assert_eq!(ft.category, FileCategory::Document);
    }

    #[test]
    fn test_detect_zip() {
        let header = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00];
        let ft = detect_file_type(&header).unwrap();
        assert_eq!(ft.mime, "application/zip");
        assert_eq!(ft.category, FileCategory::Archive);
    }

    #[test]
    fn test_detect_exe() {
        let header = b"MZ\x90\x00\x03\x00";
        let ft = detect_file_type(header).unwrap();
        assert_eq!(ft.category, FileCategory::Executable);
    }

    #[test]
    fn test_detect_sqlite() {
        let header = b"SQLite format 3\x00";
        let ft = detect_file_type(header).unwrap();
        assert_eq!(ft.mime, "application/x-sqlite3");
        assert_eq!(ft.category, FileCategory::Database);
    }

    #[test]
    fn test_detect_e01() {
        let header = [0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00];
        let ft = detect_file_type(&header).unwrap();
        assert_eq!(ft.category, FileCategory::Forensic);
    }

    #[test]
    fn test_unknown() {
        let header = [0x00, 0x00, 0x00, 0x00];
        assert!(detect_file_type(&header).is_none());
    }

    #[test]
    fn test_is_helpers() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0];
        assert!(is_image(&jpeg));
        assert!(!is_archive(&jpeg));
        
        let zip = [0x50, 0x4B, 0x03, 0x04];
        assert!(is_archive(&zip));
        assert!(!is_image(&zip));
    }
}
