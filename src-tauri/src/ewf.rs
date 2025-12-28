// EWF (Expert Witness Format) - E01/EWF/Ex01 forensic image parser
// Architecture inspired by libewf with proper segment management, file pool, and caching

#![allow(dead_code)]  // Functions used by containers.rs appear unused from examples

use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use flate2::read::ZlibDecoder;
use rayon::prelude::*;
use sha1::{Sha1, Digest};
use sha2::{Sha256, Sha512};
use blake2::Blake2b512;
use blake3::Hasher as Blake3Hasher;
use xxhash_rust::xxh3::Xxh3;
use xxhash_rust::xxh64::Xxh64;

// Debug macro - only prints when E01_DEBUG env var is set
#[allow(unused_macros)]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) && std::env::var("E01_DEBUG").is_ok() {
            eprintln!($($arg)*);
        }
    };
}

// =============================================================================
// Core Constants
// =============================================================================

#[allow(dead_code)]
const EWF_SIGNATURE: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";
#[allow(dead_code)]
const EWF2_SIGNATURE: &[u8; 8] = b"EVF2\x0d\x0a\x81\x00";
#[allow(dead_code)]
const SECTOR_SIZE: u64 = 512;
const MAX_OPEN_FILES: usize = 16; // Like libewf's rlimit handling

// =============================================================================
// File I/O Pool - Like libbfio_pool
// =============================================================================

/// Manages multiple file handles with LRU caching
/// Limits number of simultaneously open files
struct FileIoPool {
    /// Paths to all segment files in order
    file_paths: Vec<PathBuf>,
    /// Currently open file handles (file_index -> File)
    open_handles: HashMap<usize, File>,
    /// LRU queue for file handle management
    lru_queue: VecDeque<usize>,
    /// Maximum number of simultaneously open files
    max_open: usize,
}

impl FileIoPool {
    fn new(file_paths: Vec<PathBuf>, max_open: usize) -> Self {
        Self {
            file_paths,
            open_handles: HashMap::new(),
            lru_queue: VecDeque::new(),
            max_open,
        }
    }

    /// Get a file handle, opening it if necessary and managing LRU cache
    fn get_file(&mut self, file_index: usize) -> Result<&mut File, String> {
        // If file is already open, move to front of LRU queue
        if self.open_handles.contains_key(&file_index) {
            // Remove from current position in LRU
            self.lru_queue.retain(|&x| x != file_index);
            // Add to front
            self.lru_queue.push_front(file_index);
            return Ok(self.open_handles.get_mut(&file_index).unwrap());
        }

        // Need to open the file - check if we need to close one first
        if self.open_handles.len() >= self.max_open {
            // Close least recently used file
            if let Some(lru_index) = self.lru_queue.pop_back() {
                self.open_handles.remove(&lru_index);
            }
        }

        // Open the new file
        let file_path = &self.file_paths[file_index];
        let file = File::open(file_path)
            .map_err(|e| format!("Failed to open segment {}: {}", file_index, e))?;
        
        self.open_handles.insert(file_index, file);
        self.lru_queue.push_front(file_index);
        
        Ok(self.open_handles.get_mut(&file_index).unwrap())
    }

    fn get_file_count(&self) -> usize {
        self.file_paths.len()
    }
}

// =============================================================================
// Section Descriptors - EWF Format Structures
// =============================================================================

#[derive(Clone, Debug)]
struct SectionDescriptor {
    section_type: [u8; 16],
    next_offset: u64,
    size: u64,
}

#[derive(Clone, Debug)]
pub struct VolumeSection {
    pub chunk_count: u32,
    pub sectors_per_chunk: u32,
    pub bytes_per_sector: u32,
    pub sector_count: u64,
    pub compression_level: u8,
}

// =============================================================================
// Segment File - Represents one physical E01/E02 file
// =============================================================================

/// Metadata for a single segment file (like libewf_segment_file)
struct SegmentFile {
    /// Index in the file pool
    file_index: usize,
    /// Segment number (1 for E01, 2 for E02, etc.)
    #[allow(dead_code)]
    segment_number: u16,
    /// Size of this segment file in bytes
    file_size: u64,
    /// Sections found in this segment
    sections: Vec<SegmentSection>,
}

#[derive(Clone)]
struct SegmentSection {
    #[allow(dead_code)]
    section_type: String,
    /// Offset within the segment file
    #[allow(dead_code)]
    offset_in_segment: u64,
    /// Size of section data
    #[allow(dead_code)]
    size: u64,
    /// For 'sectors' sections - where chunk data starts
    data_offset: Option<u64>,
    /// For 'table' sections - parsed table data
    table_data: Option<TableSection>,
}

#[derive(Clone)]
struct TableSection {
    #[allow(dead_code)]
    chunk_count: u32,
    base_offset: u64,
    /// Offsets are relative to the most recent 'sectors' section
    offsets: Vec<u64>,
}

// =============================================================================
// Chunk Cache - Like libfcache
// =============================================================================

struct ChunkCache {
    cache: HashMap<usize, Vec<u8>>,
    lru_queue: VecDeque<usize>,
    max_entries: usize,
}

impl ChunkCache {
    fn new(max_entries: usize) -> Self {
        Self {
            cache: HashMap::new(),
            lru_queue: VecDeque::new(),
            max_entries,
        }
    }

    fn get(&mut self, chunk_index: usize) -> Option<Vec<u8>> {
        if let Some(data) = self.cache.get(&chunk_index) {
            // Move to front of LRU
            self.lru_queue.retain(|&x| x != chunk_index);
            self.lru_queue.push_front(chunk_index);
            return Some(data.clone());
        }
        None
    }

    fn insert(&mut self, chunk_index: usize, data: Vec<u8>) {
        // Remove oldest if at capacity
        if self.cache.len() >= self.max_entries {
            if let Some(old_index) = self.lru_queue.pop_back() {
                self.cache.remove(&old_index);
            }
        }

        self.cache.insert(chunk_index, data);
        self.lru_queue.push_front(chunk_index);
    }
}

// =============================================================================
// E01 Handle - Main Interface (like libewf_handle)
// =============================================================================

pub struct E01Handle {
    /// File I/O pool managing all segment files
    file_pool: FileIoPool,
    /// Parsed segment file metadata
    segments: Vec<SegmentFile>,
    /// Volume information from first segment
    volume: VolumeSection,
    /// Global chunk table mapping chunk_index -> (segment_index, section_index, chunk_in_table)
    chunk_table: Vec<ChunkLocation>,
    /// Chunk data cache
    chunk_cache: ChunkCache,
}

#[derive(Clone)]
struct ChunkLocation {
    segment_index: usize,
    #[allow(dead_code)]
    section_index: usize, // Which 'sectors' section in this segment
    #[allow(dead_code)]
    chunk_in_table: usize,
    offset: u64, // The offset value from the table (may be relative to base_offset or absolute)
    base_offset: u64, // Table base offset for EnCase 6+ (0 for older versions)
    sectors_base: u64, // Global offset of the sectors section data area
    is_delta_chunk: bool, // True if this was scanned from inline delta format
}

impl E01Handle {
    /// Open E01 file set (like libewf_handle_open)
    pub fn open(path: &str) -> Result<Self, String> {
        // Step 1: Discover all segment files (like libewf_glob)
        let segment_paths = discover_segments(path)?;
        
        // Step 2: Create file I/O pool
        let mut file_pool = FileIoPool::new(segment_paths, MAX_OPEN_FILES);
        
        // Step 3: Get segment file sizes for global offset conversion
        let mut segment_sizes = Vec::new();
        for i in 0..file_pool.get_file_count() {
            let file = file_pool.get_file(i)?;
            let size = file.metadata()
                .map_err(|e| format!("Failed to get metadata: {}", e))?
                .len();
            segment_sizes.push(size);
        }
        
        // Step 4: Parse sections globally (not per-segment!)
        let (segments, volume_info, chunk_table) = Self::parse_sections_globally(&mut file_pool, &segment_sizes)?;
        
        let volume = volume_info.ok_or("No volume section found")?;
        
        // Step 5: Create chunk cache
        let chunk_cache = ChunkCache::new(256); // Cache last 256 chunks
        
        Ok(Self {
            file_pool,
            segments,
            volume,
            chunk_table,
            chunk_cache,
        })
    }

    /// Parse sections globally across all segments (next_offset is global!)
    fn parse_sections_globally(
        file_pool: &mut FileIoPool,
        segment_sizes: &[u64],
    ) -> Result<(Vec<SegmentFile>, Option<VolumeSection>, Vec<ChunkLocation>), String> {
        // Initialize segment file structures
        let mut segments: Vec<SegmentFile> = (0..file_pool.get_file_count())
            .map(|i| SegmentFile {
                file_index: i,
                segment_number: (i + 1) as u16,
                file_size: segment_sizes[i],
                sections: Vec::new(),
            })
            .collect();
        
        let mut volume_info: Option<VolumeSection> = None;
        let mut chunk_locations = Vec::new();
        
        // Track sectors section for delta chunk scanning
        let mut sectors_data_offset: Option<u64> = None;
        let mut sectors_data_size: Option<u64> = None;
        
        // Start at offset 13 in first segment (after file header)
        let mut current_global_offset = 13u64;
        let mut last_sectors_offset: Option<u64> = None;
        let mut section_count = 0;
        const MAX_SECTIONS: u32 = 10000;
        
        debug_print!("Starting global section walk...");
        
        loop {
            if section_count >= MAX_SECTIONS {
                debug_print!("Reached max sections limit");
                break;
            }
            section_count += 1;
            
            // Convert global offset to (segment_index, offset_in_segment)
            let (mut seg_idx, offset_in_seg) = Self::global_to_segment_offset(current_global_offset, segment_sizes)?;
            
            // Check if we have enough space for section descriptor
            if offset_in_seg + 32 > segment_sizes[seg_idx] {
                debug_print!("Not enough space for section descriptor at global offset {}", current_global_offset);
                break;
            }
            
            // Read section descriptor
            let file = file_pool.get_file(seg_idx)?;
            let section_desc = match Self::read_section_descriptor(file, offset_in_seg) {
                Ok(desc) => desc,
                Err(e) => {
                    debug_print!("Failed to read section at global offset {}: {}", current_global_offset, e);
                    break;
                }
            };
            
            let section_type = String::from_utf8_lossy(&section_desc.section_type)
                .trim_matches('\0')
                .to_string();
            
            debug_print!("Section '{}' at global offset {} (seg {}, offset {})", 
                     section_type, current_global_offset, seg_idx, offset_in_seg);
            
            // Create section entry
            let mut seg_section = SegmentSection {
                section_type: section_type.clone(),
                offset_in_segment: offset_in_seg,
                size: section_desc.size,
                data_offset: None,  // Will set for sections that have data
                table_data: None,
            };
            
            // Handle different section types
            match section_type.as_str() {
                "volume" | "disk" => {
                    // Section descriptor is 76 bytes, data follows immediately
                    let data_global_offset = current_global_offset + 76;
                    let (data_seg_idx, data_offset_in_seg) = Self::global_to_segment_offset(data_global_offset, segment_sizes)?;
                    seg_section.data_offset = Some(data_global_offset);
                    
                    if volume_info.is_none() {
                        volume_info = Some(Self::read_volume_section(file_pool, data_seg_idx, data_offset_in_seg)?);
                    }
                }
                "sectors" => {
                    // Section descriptor is 76 bytes, data follows immediately
                    let data_global_offset = current_global_offset + 76;
                    seg_section.data_offset = Some(data_global_offset);
                    last_sectors_offset = Some(data_global_offset);
                    
                    // Track sectors section info for potential delta chunk scanning
                    sectors_data_offset = Some(data_global_offset);
                    // Size is section size minus header (76 bytes)
                    sectors_data_size = Some(section_desc.size.saturating_sub(76));
                }
                "table" => {
                    // Section descriptor is 76 bytes, data follows immediately
                    let data_global_offset = current_global_offset + 76;
                    let (data_seg_idx, data_offset_in_seg) = Self::global_to_segment_offset(data_global_offset, segment_sizes)?;
                    seg_section.data_offset = Some(data_global_offset);
                    
                    if let Some(sectors_base) = last_sectors_offset {
                        debug_print!("  Reading {} at seg {} offset {}, sectors_base={}", section_type, data_seg_idx, data_offset_in_seg, sectors_base);
                        let file = file_pool.get_file(data_seg_idx)?;
                        if let Ok(table) = Self::read_table_section(file, data_offset_in_seg, section_desc.size, sectors_base) {
                            debug_print!("  Table has {} chunk offsets, base_offset={}", table.offsets.len(), table.base_offset);
                            // Add chunk locations from this table
                            for (chunk_in_table, &offset) in table.offsets.iter().enumerate() {
                                chunk_locations.push(ChunkLocation {
                                    segment_index: seg_idx,
                                    section_index: segments[seg_idx].sections.len(),
                                    chunk_in_table,
                                    offset,
                                    base_offset: table.base_offset, // Table base offset from header
                                    sectors_base, // Global offset to sectors data area
                                    is_delta_chunk: false, // Table-based chunk, not delta format
                                });
                            }
                            seg_section.table_data = Some(table);
                        } else {
                            debug_print!("  Failed to read table section");
                        }
                    } else {
                        debug_print!("  Skipping {} - no sectors_base set", section_type);
                    }
                }
                "table2" => {
                    // table2 sections contain checksums, not chunk offsets - skip them
                    debug_print!("  Skipping table2 section (contains checksums)");
                }
                "done" => {
                    segments[seg_idx].sections.push(seg_section);
                    debug_print!("Reached 'done' section, stopping");
                    break;
                }
                "next" => {
                    // "next" section signals continuation to next segment
                    // The next_offset usually points to itself, meaning: continue to next file
                    if section_desc.next_offset == current_global_offset {
                        // Move to next segment file at offset 13 (after EVF header)
                        if seg_idx + 1 < segments.len() {
                            seg_idx += 1;
                            let next_segment_start: u64 = segment_sizes.iter().take(seg_idx).sum();
                            current_global_offset = next_segment_start + 13;
                            debug_print!("Moving to segment {} at global offset {}", seg_idx, current_global_offset);
                            continue;
                        } else {
                            debug_print!("No more segments, stopping");
                            break;
                        }
                    }
                }
                _ => {}
            }
            
            segments[seg_idx].sections.push(seg_section);
            
            // Move to next section
            if section_desc.next_offset == 0 || section_desc.next_offset == current_global_offset {
                debug_print!("Section chain ended");
                break;
            }
            
            // Convert next_offset to global (it's segment-local in all segments)
            let segment_start: u64 = segment_sizes.iter().take(seg_idx).sum();
            current_global_offset = segment_start + section_desc.next_offset;
        }
        
        debug_print!("Parsed {} sections, {} chunk locations", section_count, chunk_locations.len());
        
        // If no chunk locations were found but we have volume info and sectors data,
        // try to parse as delta/inline chunk format (used in highly compressed E01s)
        if chunk_locations.is_empty() {
            if let (Some(vol), Some(sectors_offset), Some(sectors_size)) = 
                (&volume_info, sectors_data_offset, sectors_data_size) 
            {
                debug_print!("No table found - attempting delta chunk scan at offset {} size {}", 
                         sectors_offset, sectors_size);
                
                if let Ok(delta_locations) = Self::scan_delta_chunks(
                    file_pool, 
                    segment_sizes, 
                    sectors_offset, 
                    sectors_size,
                    vol.chunk_count as usize,
                    vol.sectors_per_chunk,
                    vol.bytes_per_sector,
                ) {
                    debug_print!("Found {} delta chunks", delta_locations.len());
                    chunk_locations = delta_locations;
                }
            }
        }
        
        Ok((segments, volume_info, chunk_locations))
    }
    
    /// Scan for delta/inline chunks in sectors section
    /// These formats store chunks directly in the sectors area without a separate table
    fn scan_delta_chunks(
        file_pool: &mut FileIoPool,
        segment_sizes: &[u64],
        sectors_offset: u64,
        sectors_size: u64,
        expected_chunks: usize,
        sectors_per_chunk: u32,
        bytes_per_sector: u32,
    ) -> Result<Vec<ChunkLocation>, String> {
        let chunk_size = sectors_per_chunk as usize * bytes_per_sector as usize;
        let mut locations = Vec::with_capacity(expected_chunks);
        let mut current_offset = sectors_offset;
        let end_offset = sectors_offset + sectors_size;
        
        let (seg_idx, offset_in_seg) = Self::global_to_segment_offset(current_offset, segment_sizes)?;
        let file = file_pool.get_file(seg_idx)?;
        
        debug_print!("Scanning delta chunks: sectors_offset={}, sectors_size={}, expected_chunks={}, chunk_size={}", 
                 sectors_offset, sectors_size, expected_chunks, chunk_size);
        
        for chunk_idx in 0..expected_chunks {
            if current_offset >= end_offset {
                debug_print!("Delta scan reached end of sectors at chunk {}", chunk_idx);
                break;
            }
            
            let local_offset = current_offset - sectors_offset + offset_in_seg;
            
            // Read the chunk header (4 bytes: size with compression flag)
            file.seek(SeekFrom::Start(local_offset))
                .map_err(|e| format!("Seek failed at offset {}: {}", local_offset, e))?;
            
            let mut header = [0u8; 4];
            file.read_exact(&mut header)
                .map_err(|e| format!("Read header failed at offset {}: {}", local_offset, e))?;
            
            let raw_size = u32::from_le_bytes(header);
            let is_compressed = (raw_size & 0x80000000) != 0;
            let data_size = (raw_size & 0x7FFFFFFF) as u64;
            
            if chunk_idx < 5 {
                debug_print!("  Delta chunk[{}]: offset={}, raw_size={:#x}, compressed={}, data_size={}", 
                         chunk_idx, current_offset, raw_size, is_compressed, data_size);
            }
            
            // Store location - the offset points to the header, data follows
            locations.push(ChunkLocation {
                segment_index: seg_idx,
                section_index: 0,
                chunk_in_table: chunk_idx,
                offset: raw_size as u64, // Store the raw value with compression flag
                base_offset: 0,
                sectors_base: current_offset, // Global offset to this chunk's header
                is_delta_chunk: true, // This is a delta/inline chunk format
            });
            
            // Move to next chunk: header (4 bytes) + data
            current_offset += 4 + data_size;
            
            // Align to next chunk boundary if needed (some formats pad to 4-byte alignment)
            if data_size < chunk_size as u64 && !is_compressed {
                // For uncompressed, data should be exactly chunk_size, so something's wrong
                debug_print!("  Warning: uncompressed chunk smaller than expected: {} < {}", data_size, chunk_size);
            }
        }
        
        Ok(locations)
    }

    /// Convert global byte offset to (segment_index, offset_in_segment)
    fn global_to_segment_offset(global_offset: u64, segment_sizes: &[u64]) -> Result<(usize, u64), String> {
        let mut cumulative = 0u64;
        for (idx, &size) in segment_sizes.iter().enumerate() {
            if global_offset < cumulative + size {
                return Ok((idx, global_offset - cumulative));
            }
            cumulative += size;
        }
        Err(format!("Global offset {} beyond all segments", global_offset))
    }

    /// Read a chunk by global index (like libewf_handle_read_buffer)
    pub fn read_chunk(&mut self, chunk_index: usize) -> Result<Vec<u8>, String> {
        self.read_chunk_internal(chunk_index, true)
    }
    
    /// Read chunk without caching - optimized for sequential access patterns like verification
    pub fn read_chunk_no_cache(&mut self, chunk_index: usize) -> Result<Vec<u8>, String> {
        self.read_chunk_internal(chunk_index, false)
    }
    
    fn read_chunk_internal(&mut self, chunk_index: usize, use_cache: bool) -> Result<Vec<u8>, String> {
        // Check cache first (only if caching enabled)
        if use_cache {
            if let Some(cached_data) = self.chunk_cache.get(chunk_index) {
                return Ok(cached_data);
            }
        }
        
        // Calculate expected chunk size
        let chunk_size = (self.volume.sectors_per_chunk as usize) * (self.volume.bytes_per_sector as usize);
        
        // Get chunk location - if not in table, this is a sparse/zeroed chunk
        let location = match self.chunk_table.get(chunk_index) {
            Some(loc) => loc.clone(),
            None => {
                // Chunk not in table - return zeros (sparse image)
                // For the last chunk, may need to calculate actual size
                let expected_chunks = self.volume.chunk_count as usize;
                if chunk_index >= expected_chunks {
                    return Err(format!("Chunk {} beyond expected count {}", chunk_index, expected_chunks));
                }
                
                // Calculate size for last chunk (may be partial)
                let final_chunk_size = if chunk_index == expected_chunks - 1 {
                    let remaining_sectors = self.volume.sector_count % self.volume.sectors_per_chunk as u64;
                    if remaining_sectors > 0 {
                        (remaining_sectors * self.volume.bytes_per_sector as u64) as usize
                    } else {
                        chunk_size
                    }
                } else {
                    chunk_size
                };
                
                return Ok(vec![0u8; final_chunk_size]);
            }
        };
        
        // Handle sparse chunks (offset == 0 and not delta chunk mode)
        if location.offset == 0 && location.sectors_base == 0 {
            return Ok(vec![0u8; chunk_size]);
        }
        
        let segment_sizes: Vec<u64> = self.segments.iter().map(|s| s.file_size).collect();
        
        // Handle delta chunk format (inline chunks with no table section)
        // Delta chunks use sectors_base as the absolute offset to the chunk header
        let (seg_idx, offset_in_segment, is_compressed) = if location.is_delta_chunk {
            // Delta chunk format: sectors_base is absolute offset to chunk header
            // offset contains the raw size value with compression flag
            let is_compressed = (location.offset & 0x80000000) != 0;
            
            // Skip the 4-byte header to get to the actual data
            let data_offset = location.sectors_base + 4;
            
            let (seg_idx, offset_in_seg) = Self::global_to_segment_offset(data_offset, &segment_sizes)
                .map_err(|e| format!("Delta chunk {}: offset {} error: {}", chunk_index, data_offset, e))?;
            
            if chunk_index < 3 {
                debug_print!("Delta chunk {}: sectors_base={} data_offset={} compressed={} seg={} local={}", 
                         chunk_index, location.sectors_base, data_offset, is_compressed, seg_idx, offset_in_seg);
            }
            
            (seg_idx, offset_in_seg, is_compressed)
        } else {
            // Traditional table-based format
            // Extract compression flag and actual offset
            let is_compressed = (location.offset & 0x80000000) != 0;
            let offset_value = (location.offset & 0x7FFFFFFF) as u64;
            
            // For EnCase 1-5: offsets are segment-local (relative to start of the segment containing the table)
            // For EnCase 6+: offsets are relative to table base_offset
            // libewf uses: file_offset = base_offset + current_offset
            // where base_offset=0 for EnCase 1-5, so file_offset = current_offset (segment-local)
            let segment_local_offset = if location.base_offset > 0 {
                // EnCase 6+: base_offset + table offset
                location.base_offset + offset_value
            } else {
                // EnCase 1-5: offset is segment-local
                offset_value
            };
            
            // Convert segment-local offset to global offset
            // The offset is relative to the start of the segment containing the table
            let segment_start: u64 = segment_sizes.iter().take(location.segment_index).sum();
            let absolute_offset = segment_start + segment_local_offset;
            
            // Chunk offsets are now absolute within the segment file
            let (seg_idx, offset_in_segment) = match Self::global_to_segment_offset(absolute_offset, &segment_sizes) {
                Ok(result) => result,
                Err(e) => {
                    debug_print!("Chunk {}: offset={:#x} compressed={} offset_value={} segment_local={} absolute={} ERROR: {}", 
                             chunk_index, location.offset, is_compressed, offset_value, segment_local_offset, absolute_offset, e);
                    return Err(e);
                }
            };
            
            // Debug first few chunks
            if chunk_index < 3 {
                debug_print!("Chunk {}: offset={:#x} compressed={} offset_value={} base_offset={} sectors_base={} absolute={} seg={} local={}", 
                         chunk_index, location.offset, is_compressed, offset_value, location.base_offset, location.sectors_base, absolute_offset, seg_idx, offset_in_segment);
            }
            
            (seg_idx, offset_in_segment, is_compressed)
        };
        
        // Read the chunk data
        let file = self.file_pool.get_file(self.segments[seg_idx].file_index)?;
        
        file.seek(SeekFrom::Start(offset_in_segment))
            .map_err(|e| format!("Seek to chunk {} at offset {} failed: {}", chunk_index, offset_in_segment, e))?;
        
        // Decompress if needed (chunk_size was calculated at start of function)
        let mut chunk_data = if is_compressed {
            // For compressed data, use streaming decompression for best pipeline efficiency
            let mut decoder = ZlibDecoder::new(file.take(chunk_size as u64 * 2));
            let mut decompressed = Vec::with_capacity(chunk_size);
            decoder.read_to_end(&mut decompressed)
                .map_err(|e| format!("Chunk {} decompression failed at offset {}: {}", chunk_index, offset_in_segment, e))?;
            decompressed
        } else {
            // Uncompressed chunk - read exactly what we need
            let mut uncompressed = vec![0u8; chunk_size];
            file.read_exact(&mut uncompressed)
                .map_err(|e| format!("Read uncompressed chunk failed: {}", e))?;
            uncompressed
        };
        
        // For the last chunk, truncate to actual size
        // Total sectors in image: self.volume.sector_count
        // Sectors per chunk: self.volume.sectors_per_chunk
        let expected_chunks = self.volume.sector_count.div_ceil(self.volume.sectors_per_chunk as u64);
        if chunk_index == (expected_chunks as usize - 1) {
            // This is the last chunk - may be partial
            let remaining_sectors = self.volume.sector_count % self.volume.sectors_per_chunk as u64;
            if remaining_sectors > 0 {
                let final_size = (remaining_sectors * self.volume.bytes_per_sector as u64) as usize;
                debug_print!("Last chunk {}: original size={}, remaining_sectors={}, truncating to {}", 
                         chunk_index, chunk_data.len(), remaining_sectors, final_size);
                if chunk_data.len() > final_size {
                    chunk_data.truncate(final_size);
                }
            }
        }
        
        // Cache the result (only if caching enabled)
        if use_cache {
            self.chunk_cache.insert(chunk_index, chunk_data.clone());
        }
        
        Ok(chunk_data)
    }

    pub fn get_volume_info(&self) -> &VolumeSection {
        &self.volume
    }

    pub fn get_chunk_count(&self) -> usize {
        // Return expected chunks from volume info, not just what's in the table
        // Sparse images may have fewer chunks in the table than expected
        self.volume.chunk_count as usize
    }
    
    /// Get the number of chunks actually stored in the table
    /// (may be less than get_chunk_count for sparse images)
    pub fn get_stored_chunk_count(&self) -> usize {
        self.chunk_table.len()
    }

    // Helper methods
    fn read_section_descriptor(file: &mut File, offset: u64) -> Result<SectionDescriptor, String> {
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Seek failed: {}", e))?;
        
        let mut section_type = [0u8; 16];
        file.read_exact(&mut section_type)
            .map_err(|e| format!("Read section type failed: {}", e))?;
        
        let next_offset = read_u64(file)?;
        let size = read_u64(file)?;
        
        Ok(SectionDescriptor {
            section_type,
            next_offset,
            size,
        })
    }

    fn read_volume_section(file_pool: &mut FileIoPool, file_index: usize, offset: u64) -> Result<VolumeSection, String> {
        debug_print!("read_volume_section: file_index={}, offset={}", file_index, offset);
        
        let file = file_pool.get_file(file_index)?;
        
        // Seek to section data (offset is already past the 76-byte descriptor)
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Seek failed: {}", e))?;
        
        debug_print!("About to read volume fields at offset {}", offset);
        
        // DEBUG: Read and display raw bytes
        let mut raw_bytes = [0u8; 20];
        file.read_exact(&mut raw_bytes)
            .map_err(|e| format!("Read raw bytes failed: {}", e))?;
        debug_print!("Raw volume bytes: {:02x?}", &raw_bytes);
        
        // Seek back to re-read the same data
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Re-seek failed: {}", e))?;
        
        // Read EWF volume/disk section format:
        // Based on actual file structure analysis:
        // Offset 0x00: media_type + padding (4 bytes) - SKIP
        // Offset 0x04: chunk_count (4 bytes, little-endian)
        // Offset 0x08: sectors_per_chunk (4 bytes)
        // Offset 0x0C: bytes_per_sector (4 bytes)
        // Offset 0x10: sector_count (8 bytes, little-endian)
        
        let _media_and_padding = read_u32(file)?; // Skip media type + padding
        let chunk_count = read_u32(file)?;
        let sectors_per_chunk = read_u32(file)?;
        let bytes_per_sector = read_u32(file)?;
        let sector_count = read_u64(file)?;
        
        debug_print!("Volume: chunk_count={}, sectors_per_chunk={}, bytes_per_sector={}, sector_count={}", 
                 chunk_count, sectors_per_chunk, bytes_per_sector, sector_count);
        
        debug_print!("Volume section: chunk_count={}, sectors_per_chunk={}, bytes_per_sector={}, sector_count={}", 
                 chunk_count, sectors_per_chunk, bytes_per_sector, sector_count);
        
        Ok(VolumeSection {
            chunk_count,
            sectors_per_chunk,
            bytes_per_sector,
            sector_count,
            compression_level: 1,
        })
    }

    fn read_table_section(file: &mut File, offset: u64, size: u64, _sectors_base: u64) -> Result<TableSection, String> {
        // Seek to data offset (already past 32-byte section descriptor)
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Seek failed: {}", e))?;
        
        // Read and dump raw table header bytes
        let mut header_bytes = [0u8; 24];
        file.read_exact(&mut header_bytes)
            .map_err(|e| format!("Read header failed: {}", e))?;
        
        debug_print!("    Raw table header bytes: {:02x?}", &header_bytes);
        
        // Parse header
        let entry_count = u32::from_le_bytes([header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]]);
        let base_offset = u64::from_le_bytes([
            header_bytes[8], header_bytes[9], header_bytes[10], header_bytes[11],
            header_bytes[12], header_bytes[13], header_bytes[14], header_bytes[15]
        ]);
        
        // Use entry_count from header (libewf uses this field)
        // Note: For very old formats, this might be 0 or 1, in which case we'd need to calculate from size
        let chunk_count = if entry_count > 0 {
            entry_count
        } else {
            // Fallback: calculate from size
            ((size.saturating_sub(24 + 4)) / 4) as u32
        };
        
        debug_print!("    Table: entry_count={}, base_offset={}, using_count={}", 
                 entry_count, base_offset, chunk_count);
        debug_print!("    About to read {} offsets starting at file position {}", chunk_count, offset + 24);
        
        let mut offsets = Vec::with_capacity(chunk_count as usize);
        for i in 0..chunk_count {
            // Table entry offsets are stored in LITTLE-ENDIAN (confirmed by libewf debug)
            let raw_offset = read_u32(file)? as u64;
            offsets.push(raw_offset);
            
            // Debug first few offsets with file position
            if i < 5 {
                let is_compressed = (raw_offset & 0x80000000) != 0;
                let offset_value = raw_offset & 0x7FFFFFFF;
                let current_pos = file.stream_position().unwrap_or(0);
                debug_print!("      Offset[{}] at file_pos={}: raw={:#x} compressed={} value={}", 
                         i, current_pos - 4, raw_offset, is_compressed, offset_value);
            }
        }
        
        Ok(TableSection {
            chunk_count,
            base_offset,
            offsets,
        })
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn discover_segments(base_path: &str) -> Result<Vec<PathBuf>, String> {
    let path = Path::new(base_path);
    let parent = path.parent().ok_or("Invalid path")?;
    let stem = path.file_stem().ok_or("No filename")?.to_string_lossy();
    
    let mut paths = vec![path.to_path_buf()];
    
    for i in 2..=999 {
        let segment_name = if i <= 99 {
            format!("{}.E{:02}", stem, i)
        } else {
            format!("{}.Ex{:02}", stem, i - 99)
        };
        
        let segment_path = parent.join(&segment_name);
        if segment_path.exists() {
            paths.push(segment_path);
        } else {
            break;
        }
    }
    
    Ok(paths)
}

fn read_u32(file: &mut File) -> Result<u32, String> {
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Read u32 failed: {}", e))?;
    Ok(u32::from_le_bytes(buf))
}

// Read u32 in BIG-ENDIAN format (used for table entry offsets in EWF)
#[allow(dead_code)]
fn read_u32_be(file: &mut File) -> Result<u32, String> {
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Read u32 BE failed: {}", e))?;
    Ok(u32::from_be_bytes(buf))
}

fn read_u64(file: &mut File) -> Result<u64, String> {
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Read u64 failed: {}", e))?;
    Ok(u64::from_le_bytes(buf))
}

// =============================================================================
// Public API
// =============================================================================

#[derive(Serialize)]
pub struct E01Info {
    pub segment_count: u32,
    pub chunk_count: u32,
    pub sector_count: u64,
    pub bytes_per_sector: u32,
    pub sectors_per_chunk: u32,
}

pub fn info(path: &str) -> Result<E01Info, String> {
    let handle = E01Handle::open(path)?;
    let volume = handle.get_volume_info();
    
    Ok(E01Info {
        segment_count: handle.file_pool.get_file_count() as u32,
        chunk_count: handle.get_chunk_count() as u32,
        sector_count: volume.sector_count,
        bytes_per_sector: volume.bytes_per_sector,
        sectors_per_chunk: volume.sectors_per_chunk,
    })
}

/// Check if a file is a valid E01/EWF format image
pub fn is_e01(path: &str) -> Result<bool, String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Ok(false);
    }
    
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let mut sig = [0u8; 8];
    if file.read_exact(&mut sig).is_err() {
        return Ok(false);
    }
    
    // Check for EVF (EWF1) or EVF2 (EWF2) signature
    Ok(&sig == EWF_SIGNATURE || &sig == EWF2_SIGNATURE)
}

/// VerifyEntry for container verification results
#[derive(Serialize)]
pub struct VerifyResult {
    pub chunk_index: usize,
    pub status: String,
    pub message: Option<String>,
}

/// Verify image and return detailed results for each chunk (used by containers.rs)
pub fn verify_chunks(path: &str, algorithm: &str) -> Result<Vec<VerifyResult>, String> {
    let hash = verify_with_progress(path, algorithm, |_, _| {})?;
    
    // Return single result with final hash
    Ok(vec![VerifyResult {
        chunk_index: 0,
        status: "ok".to_string(),
        message: Some(hash),
    }])
}

/// Extract image contents to a raw file
pub fn extract(path: &str, output_dir: &str) -> Result<(), String> {
    use std::io::Write;
    
    let mut handle = E01Handle::open(path)?;
    let volume = handle.get_volume_info();
    let chunk_count = handle.get_chunk_count();
    
    // Create output filename based on input path
    let input_path = Path::new(path);
    let stem = input_path.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "image".to_string());
    
    let output_path = Path::new(output_dir).join(format!("{}.raw", stem));
    let mut output = File::create(&output_path)
        .map_err(|e| format!("Failed to create output file: {}", e))?;
    
    // Calculate total bytes to write
    let total_bytes = volume.sector_count * volume.bytes_per_sector as u64;
    let mut bytes_written = 0u64;
    
    // Extract each chunk
    for i in 0..chunk_count {
        let chunk_data = handle.read_chunk_no_cache(i)?;
        
        // For the last chunk, we may need to truncate
        let bytes_to_write = if bytes_written + chunk_data.len() as u64 > total_bytes {
            (total_bytes - bytes_written) as usize
        } else {
            chunk_data.len()
        };
        
        output.write_all(&chunk_data[..bytes_to_write])
            .map_err(|e| format!("Failed to write to output: {}", e))?;
        
        bytes_written += bytes_to_write as u64;
        
        if bytes_written >= total_bytes {
            break;
        }
    }
    
    Ok(())
}

pub fn verify(path: &str, _algorithm: &str) -> Result<String, String> {
    verify_with_progress(path, _algorithm, |_current, _total| {})
}

pub fn verify_with_progress<F>(path: &str, _algorithm: &str, progress_callback: F) -> Result<String, String> 
where
    F: FnMut(usize, usize)
{
    // Use parallel chunk processing across all cores
    verify_with_progress_parallel_chunks(path, _algorithm, progress_callback)
}

/// Pipelined parallel verification: overlap decompression and hashing for max CPU utilization
fn verify_with_progress_parallel_chunks<F>(path: &str, algorithm: &str, mut progress_callback: F) -> Result<String, String> 
where
    F: FnMut(usize, usize)
{
    use std::sync::mpsc;
    use std::thread;
    
    let handle = E01Handle::open(path)?;
    let chunk_count = handle.get_chunk_count();
    
    // Create hasher based on algorithm
    let algorithm_lower = algorithm.to_lowercase();
    let use_sha1 = algorithm_lower == "sha1" || algorithm_lower == "sha-1";
    let use_sha256 = algorithm_lower == "sha256" || algorithm_lower == "sha-256";
    let use_sha512 = algorithm_lower == "sha512" || algorithm_lower == "sha-512";
    let use_blake3 = algorithm_lower == "blake3";
    let use_blake2 = algorithm_lower == "blake2" || algorithm_lower == "blake2b";
    let use_xxh3 = algorithm_lower == "xxh3" || algorithm_lower == "xxhash3";
    let use_xxh64 = algorithm_lower == "xxh64" || algorithm_lower == "xxhash64";
    let use_crc32 = algorithm_lower == "crc32";
    
    // Report progress less frequently - batch reporting to reduce overhead
    let report_interval = 5000.max(chunk_count / 20);
    let mut last_reported = 0;
    
    // Clone path for thread safety
    let path_str = path.to_string();
    
    // Process chunks in parallel batches
    let num_threads = rayon::current_num_threads();
    // OPTIMIZATION: Smaller batches = more parallelism, more pipeline stages active
    let batch_size = num_threads * 128; // Reduced from 256 to 128 for better overlap
    
    debug_print!("Pipelined verification: {} chunks, {} threads, batch_size={}", 
                 chunk_count, num_threads, batch_size);
    
    // Create channel for pipeline: decompression -> hashing
    // OPTIMIZATION: Increased buffer to 4 batches for maximum overlap
    // This keeps decompression threads busy while hashing happens
    let (tx, rx) = mpsc::sync_channel::<Result<(usize, Vec<Vec<u8>>), String>>(4);
    
    // Configure rayon to use all cores aggressively
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .ok(); // Ignore if already initialized
    
    // Spawn decompression thread pool
    let decompression_handle = thread::spawn(move || {
        // Pre-create handle pool (one per thread)
        let handles_result: Result<Vec<E01Handle>, String> = (0..num_threads)
            .map(|_| E01Handle::open(&path_str))
            .collect();
        
        let mut handles = match handles_result {
            Ok(h) => h,
            Err(e) => {
                let _ = tx.send(Err(e));
                return;
            }
        };
        
        // Process batches and send to hashing thread
        for batch_start in (0..chunk_count).step_by(batch_size) {
            let batch_end = (batch_start + batch_size).min(chunk_count);
            let batch_chunk_count = batch_end - batch_start;
            
            // OPTIMIZATION: Parallel decompression with aggressive chunking
            // Each thread gets roughly equal work
            let thread_results: Vec<Result<Vec<(usize, Vec<u8>)>, String>> = handles
                .par_iter_mut()
                .enumerate()
                .map(|(thread_id, thread_handle)| {
                    let chunks_for_thread = batch_chunk_count.div_ceil(num_threads);
                    let mut chunks = Vec::with_capacity(chunks_for_thread);
                    
                    // Interleaved processing for better load balance
                    for chunk_idx in (batch_start + thread_id..batch_end).step_by(num_threads) {
                        match thread_handle.read_chunk_no_cache(chunk_idx) {
                            Ok(chunk_data) => chunks.push((chunk_idx, chunk_data)),
                            Err(e) => return Err(e),
                        }
                    }
                    
                    Ok(chunks)
                })
                .collect();
            
            // Collect and sort
            let mut indexed_chunks = Vec::with_capacity(batch_chunk_count);
            for result in thread_results {
                match result {
                    Ok(mut thread_chunks) => indexed_chunks.append(&mut thread_chunks),
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        return;
                    }
                }
            }
            
            indexed_chunks.sort_unstable_by_key(|(idx, _)| *idx);
            let batch_data: Vec<Vec<u8>> = indexed_chunks.into_iter().map(|(_, data)| data).collect();
            
            // Send to hashing thread (will block if buffer full, providing backpressure)
            if tx.send(Ok((batch_start, batch_data))).is_err() {
                return; // Hashing thread closed channel (error occurred)
            }
        }
    });
    
    // Hash on main thread - we MUST maintain sequential order for E01 compatibility
    // However, we can use SIMD and optimize the sequential path
    let is_known_algo = use_sha1 || use_sha256 || use_sha512 || use_blake3 || use_blake2 || use_xxh3 || use_xxh64 || use_crc32;
    let mut md5_hasher = if !is_known_algo { Some(md5::Context::new()) } else { None };
    let mut sha1_hasher = if use_sha1 { Some(Sha1::new()) } else { None };
    let mut sha256_hasher = if use_sha256 { Some(Sha256::new()) } else { None };
    let mut sha512_hasher = if use_sha512 { Some(Sha512::new()) } else { None };
    let mut blake3_hasher = if use_blake3 { Some(Blake3Hasher::new()) } else { None };
    let mut blake2_hasher = if use_blake2 { Some(Blake2b512::new()) } else { None };
    let mut xxh3_hasher = if use_xxh3 { Some(Xxh3::new()) } else { None };
    let mut xxh64_hasher = if use_xxh64 { Some(Xxh64::new(0)) } else { None };
    let mut crc32_hasher = if use_crc32 { Some(crc32fast::Hasher::new()) } else { None };
    
    // Receive and hash batches as they arrive
    while let Ok(batch_result) = rx.recv() {
        match batch_result {
            Ok((batch_start, batch_chunks)) => {
                // Sequential hashing (required for E01 format compatibility)
                // The hardware-accelerated SHA-NI makes this very fast already
                for (relative_idx, chunk_data) in batch_chunks.iter().enumerate() {
                    let chunk_idx = batch_start + relative_idx;
                    
                    // Update the appropriate hasher
                    if let Some(ref mut hasher) = md5_hasher {
                        hasher.consume(chunk_data);
                    } else if let Some(ref mut hasher) = sha1_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = sha256_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = sha512_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = blake3_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = blake2_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = xxh3_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = xxh64_hasher {
                        hasher.update(chunk_data);
                    } else if let Some(ref mut hasher) = crc32_hasher {
                        hasher.update(chunk_data);
                    }
                    
                    // Report progress
                    if chunk_idx >= last_reported + report_interval || chunk_idx == chunk_count - 1 {
                        progress_callback(chunk_idx + 1, chunk_count);
                        last_reported = chunk_idx;
                    }
                }
            }
            Err(e) => {
                // Wait for decompression thread to finish
                let _ = decompression_handle.join();
                return Err(e);
            }
        }
    }
    
    // Wait for decompression thread to complete
    decompression_handle.join().map_err(|_| "Decompression thread panicked".to_string())?;
    
    // Return the hash result
    if let Some(hasher) = md5_hasher {
        Ok(format!("{:x}", hasher.compute()))
    } else if let Some(hasher) = sha1_hasher {
        Ok(format!("{:x}", hasher.finalize()))
    } else if let Some(hasher) = sha256_hasher {
        Ok(format!("{:x}", hasher.finalize()))
    } else if let Some(hasher) = sha512_hasher {
        Ok(format!("{:x}", hasher.finalize()))
    } else if let Some(hasher) = blake3_hasher {
        Ok(format!("{}", hasher.finalize().to_hex()))
    } else if let Some(hasher) = blake2_hasher {
        Ok(format!("{:x}", hasher.finalize()))
    } else if let Some(hasher) = xxh3_hasher {
        Ok(format!("{:016x}", hasher.digest128()))
    } else if let Some(hasher) = xxh64_hasher {
        Ok(format!("{:016x}", hasher.digest()))
    } else if let Some(hasher) = crc32_hasher {
        Ok(format!("{:08x}", hasher.finalize()))
    } else {
        Err("Unknown hash algorithm".to_string())
    }
}
