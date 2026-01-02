//! Hex dump formatting utilities
//!
//! Provides hex dump display for binary data viewing in forensic analysis.
//! Essential for examining file headers, raw bytes, and binary structures.

use serde::Serialize;

// =============================================================================
// Configuration
// =============================================================================

/// Options for hex dump formatting
#[derive(Debug, Clone, Serialize)]
pub struct HexDumpOptions {
    /// Bytes per line (default: 16)
    pub bytes_per_line: usize,
    /// Show ASCII representation on right side
    pub show_ascii: bool,
    /// Show offset column on left side
    pub show_offset: bool,
    /// Use uppercase hex (A-F vs a-f)
    pub uppercase: bool,
    /// Group bytes (e.g., 2 for "AB CD", 4 for "ABCD EF01")
    pub group_size: usize,
    /// Starting offset for display (useful for showing position in file)
    pub start_offset: u64,
}

impl Default for HexDumpOptions {
    fn default() -> Self {
        Self {
            bytes_per_line: 16,
            show_ascii: true,
            show_offset: true,
            uppercase: true,
            group_size: 1,
            start_offset: 0,
        }
    }
}

impl HexDumpOptions {
    /// Create options for compact output (no ASCII, no offset)
    pub fn compact() -> Self {
        Self {
            bytes_per_line: 32,
            show_ascii: false,
            show_offset: false,
            uppercase: true,
            group_size: 1,
            start_offset: 0,
        }
    }

    /// Create options for traditional hex dump style
    pub fn traditional() -> Self {
        Self::default()
    }

    /// Create options for wide display (32 bytes per line)
    pub fn wide() -> Self {
        Self {
            bytes_per_line: 32,
            show_ascii: true,
            show_offset: true,
            uppercase: true,
            group_size: 2,
            start_offset: 0,
        }
    }

    /// Builder: set bytes per line
    pub fn with_bytes_per_line(mut self, n: usize) -> Self {
        self.bytes_per_line = n.max(1);
        self
    }

    /// Builder: set starting offset
    pub fn with_start_offset(mut self, offset: u64) -> Self {
        self.start_offset = offset;
        self
    }

    /// Builder: enable/disable ASCII display
    pub fn with_ascii(mut self, show: bool) -> Self {
        self.show_ascii = show;
        self
    }

    /// Builder: enable/disable offset column
    pub fn with_offset(mut self, show: bool) -> Self {
        self.show_offset = show;
        self
    }
}

// =============================================================================
// Hex Dump Formatting
// =============================================================================

/// Format binary data as a hex dump string
///
/// # Example Output (default options):
/// ```text
/// 00000000  50 4B 03 04 14 00 00 00  08 00 5B 7A 9E 58 AB CD  |PK........[z.X..|
/// 00000010  EF 01 23 45 67 89 AB CD  EF 01 23 45 67 89 AB CD  |..#Eg.....#Eg...|
/// ```
pub fn format_hex_dump(data: &[u8], options: &HexDumpOptions) -> String {
    if data.is_empty() {
        return String::from("(empty)");
    }

    let mut result = String::with_capacity(data.len() * 4);
    let bytes_per_line = options.bytes_per_line.max(1);

    for (chunk_idx, chunk) in data.chunks(bytes_per_line).enumerate() {
        let offset = options.start_offset + (chunk_idx * bytes_per_line) as u64;

        // Offset column
        if options.show_offset {
            result.push_str(&format!("{:08X}  ", offset));
        }

        // Hex bytes
        for (i, byte) in chunk.iter().enumerate() {
            if options.uppercase {
                result.push_str(&format!("{:02X}", byte));
            } else {
                result.push_str(&format!("{:02x}", byte));
            }

            // Grouping/spacing
            if options.group_size > 0 && (i + 1) % options.group_size == 0 && i + 1 < bytes_per_line {
                result.push(' ');
            }

            // Extra space at midpoint for readability
            if i + 1 == bytes_per_line / 2 && bytes_per_line >= 16 {
                result.push(' ');
            }
        }

        // Pad incomplete lines
        if chunk.len() < bytes_per_line {
            let missing = bytes_per_line - chunk.len();
            let spaces_per_byte = if options.group_size > 0 { 2 + 1 } else { 2 };
            result.push_str(&" ".repeat(missing * spaces_per_byte));
            
            // Account for midpoint space if we didn't reach it
            if chunk.len() <= bytes_per_line / 2 && bytes_per_line >= 16 {
                result.push(' ');
            }
        }

        // ASCII column
        if options.show_ascii {
            result.push_str(" |");
            for byte in chunk {
                if *byte >= 0x20 && *byte < 0x7F {
                    result.push(*byte as char);
                } else {
                    result.push('.');
                }
            }
            // Pad ASCII for incomplete lines
            if chunk.len() < bytes_per_line {
                result.push_str(&" ".repeat(bytes_per_line - chunk.len()));
            }
            result.push('|');
        }

        result.push('\n');
    }

    result
}

/// Format a single line of hex (no offset, no ASCII) - useful for inline display
pub fn format_hex_inline(data: &[u8], uppercase: bool) -> String {
    if uppercase {
        data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
    } else {
        data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
    }
}

/// Format bytes as continuous hex string (no spaces)
pub fn format_hex_string(data: &[u8], uppercase: bool) -> String {
    if uppercase {
        data.iter().map(|b| format!("{:02X}", b)).collect()
    } else {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Parse hex string back to bytes
pub fn parse_hex_string(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.replace(" ", "").replace("\n", "").replace("\r", "");
    
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}

// =============================================================================
// Hex Dump Result (for Tauri commands)
// =============================================================================

/// Structured hex dump result for frontend display
#[derive(Debug, Clone, Serialize)]
pub struct HexDumpResult {
    /// Formatted hex dump string
    pub formatted: String,
    /// Total bytes in the data
    pub total_bytes: usize,
    /// Starting offset
    pub start_offset: u64,
    /// Ending offset
    pub end_offset: u64,
    /// Number of lines
    pub line_count: usize,
}

/// Create a structured hex dump result
pub fn create_hex_dump(data: &[u8], options: &HexDumpOptions) -> HexDumpResult {
    let formatted = format_hex_dump(data, options);
    let bytes_per_line = options.bytes_per_line.max(1);
    let line_count = (data.len() + bytes_per_line - 1) / bytes_per_line;

    HexDumpResult {
        formatted,
        total_bytes: data.len(),
        start_offset: options.start_offset,
        end_offset: options.start_offset + data.len() as u64,
        line_count,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_dump_basic() {
        let data = b"Hello, World!";
        let dump = format_hex_dump(data, &HexDumpOptions::default());
        assert!(dump.contains("48 65 6C 6C 6F")); // "Hello" in hex
        assert!(dump.contains("|Hello, World!"));
    }

    #[test]
    fn test_hex_dump_non_printable() {
        let data = &[0x00, 0x01, 0x02, 0xFF, 0x20, 0x41];
        let dump = format_hex_dump(data, &HexDumpOptions::default());
        assert!(dump.contains("00 01 02 FF 20 41"));
        assert!(dump.contains("|.... A")); // Non-printable as dots, space is printable, A is printable
    }

    #[test]
    fn test_hex_inline() {
        let data = &[0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(format_hex_inline(data, true), "DE AD BE EF");
        assert_eq!(format_hex_inline(data, false), "de ad be ef");
    }

    #[test]
    fn test_hex_string() {
        let data = &[0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(format_hex_string(data, true), "DEADBEEF");
        assert_eq!(format_hex_string(data, false), "deadbeef");
    }

    #[test]
    fn test_parse_hex_string() {
        assert_eq!(parse_hex_string("DEADBEEF").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(parse_hex_string("de ad be ef").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(parse_hex_string("DEA").is_err()); // Odd length
        assert!(parse_hex_string("GHIJ").is_err()); // Invalid hex
    }

    #[test]
    fn test_empty_data() {
        let dump = format_hex_dump(&[], &HexDumpOptions::default());
        assert_eq!(dump, "(empty)");
    }
}
