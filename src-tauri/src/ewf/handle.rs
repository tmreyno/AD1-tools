//! E01Handle - Main interface for E01 file access (like libewf_handle)

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use flate2::read::ZlibDecoder;
use tracing::trace;

use crate::common::{
    FileIoPool,
    binary::{read_u32_le, read_u64_le},
    segments::discover_e01_segments,
};

use super::types::*;
use super::cache::ChunkCache;

// =============================================================================
// E01 Handle - Main Interface (like libewf_handle)
// =============================================================================

pub struct E01Handle {
    /// File I/O pool managing all segment files
    pub(crate) file_pool: FileIoPool,
    /// Parsed segment file metadata
    pub(crate) segments: Vec<SegmentFile>,
    /// Volume information from first segment
    pub(crate) volume: VolumeSection,
    /// Global chunk table mapping chunk_index -> (segment_index, section_index, chunk_in_table)
    pub(crate) chunk_table: Vec<ChunkLocation>,
    /// Chunk data cache
    chunk_cache: ChunkCache,
    /// Stored image hashes from hash/digest sections
    pub(crate) stored_hashes: Vec<StoredImageHash>,
}

impl E01Handle {
    /// Open E01 file set (like libewf_handle_open)
    pub fn open(path: &str) -> Result<Self, String> {
        // Step 1: Discover all segment files (like libewf_glob)
        let segment_paths = discover_e01_segments(path)?;
        
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
        let (segments, volume_info, chunk_table, stored_hashes) = Self::parse_sections_globally(&mut file_pool, &segment_sizes)?;
        
        let volume = volume_info.ok_or("No volume section found")?;
        
        // Step 5: Create chunk cache
        let chunk_cache = ChunkCache::new(256); // Cache last 256 chunks
        
        Ok(Self {
            file_pool,
            segments,
            volume,
            chunk_table,
            chunk_cache,
            stored_hashes,
        })
    }

    /// Parse sections globally across all segments (next_offset is global!)
    fn parse_sections_globally(
        file_pool: &mut FileIoPool,
        segment_sizes: &[u64],
    ) -> Result<(Vec<SegmentFile>, Option<VolumeSection>, Vec<ChunkLocation>, Vec<StoredImageHash>), String> {
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
        let mut stored_hashes: Vec<StoredImageHash> = Vec::new();
        
        // Track sectors section for delta chunk scanning
        let mut sectors_data_offset: Option<u64> = None;
        let mut sectors_data_size: Option<u64> = None;
        
        // Start at offset 13 in first segment (after file header)
        let mut current_global_offset = 13u64;
        let mut last_sectors_offset: Option<u64> = None;
        let mut section_count = 0;
        const MAX_SECTIONS: u32 = 10000;
        
        trace!("Starting global section walk...");
        
        loop {
            if section_count >= MAX_SECTIONS {
                trace!("Reached max sections limit");
                break;
            }
            section_count += 1;
            
            // Convert global offset to (segment_index, offset_in_segment)
            let (mut seg_idx, offset_in_seg) = Self::global_to_segment_offset(current_global_offset, segment_sizes)?;
            
            // Check if we have enough space for section descriptor
            if offset_in_seg + 32 > segment_sizes[seg_idx] {
                trace!("Not enough space for section descriptor at global offset {}", current_global_offset);
                break;
            }
            
            // Read section descriptor
            let file = file_pool.get_file(seg_idx)?;
            let section_desc = match Self::read_section_descriptor(file, offset_in_seg) {
                Ok(desc) => desc,
                Err(e) => {
                    trace!("Failed to read section at global offset {}: {}", current_global_offset, e);
                    break;
                }
            };
            
            let section_type = String::from_utf8_lossy(&section_desc.section_type)
                .trim_matches('\0')
                .to_string();
            
            trace!("Section '{}' at global offset {} (seg {}, offset {})", 
                     section_type, current_global_offset, seg_idx, offset_in_seg);
            
            // Create section entry
            let mut seg_section = SegmentSection {
                section_type: section_type.clone(),
                offset_in_segment: offset_in_seg,
                size: section_desc.size,
                data_offset: None,
                table_data: None,
            };
            
            // Handle different section types
            match section_type.as_str() {
                "volume" | "disk" => {
                    let data_global_offset = current_global_offset + 76;
                    let (data_seg_idx, data_offset_in_seg) = Self::global_to_segment_offset(data_global_offset, segment_sizes)?;
                    seg_section.data_offset = Some(data_global_offset);
                    
                    if volume_info.is_none() {
                        volume_info = Some(Self::read_volume_section(file_pool, data_seg_idx, data_offset_in_seg)?);
                    }
                }
                "sectors" => {
                    let data_global_offset = current_global_offset + 76;
                    seg_section.data_offset = Some(data_global_offset);
                    last_sectors_offset = Some(data_global_offset);
                    
                    sectors_data_offset = Some(data_global_offset);
                    sectors_data_size = Some(section_desc.size.saturating_sub(76));
                }
                "table" => {
                    let data_global_offset = current_global_offset + 76;
                    let (data_seg_idx, data_offset_in_seg) = Self::global_to_segment_offset(data_global_offset, segment_sizes)?;
                    seg_section.data_offset = Some(data_global_offset);
                    
                    if let Some(sectors_base) = last_sectors_offset {
                        trace!("  Reading {} at seg {} offset {}, sectors_base={}", section_type, data_seg_idx, data_offset_in_seg, sectors_base);
                        let file = file_pool.get_file(data_seg_idx)?;
                        if let Ok(table) = Self::read_table_section(file, data_offset_in_seg, section_desc.size, sectors_base) {
                            trace!("  Table has {} chunk offsets, base_offset={}", table.offsets.len(), table.base_offset);
                            for (chunk_in_table, &offset) in table.offsets.iter().enumerate() {
                                chunk_locations.push(ChunkLocation {
                                    segment_index: seg_idx,
                                    section_index: segments[seg_idx].sections.len(),
                                    chunk_in_table,
                                    offset,
                                    base_offset: table.base_offset,
                                    sectors_base,
                                    is_delta_chunk: false,
                                });
                            }
                            seg_section.table_data = Some(table);
                        } else {
                            trace!("  Failed to read table section");
                        }
                    } else {
                        trace!("  Skipping {} - no sectors_base set", section_type);
                    }
                }
                "table2" => {
                    trace!("  Skipping table2 section (contains checksums)");
                }
                "hash" => {
                    let data_global_offset = current_global_offset + 76;
                    let (data_seg_idx, data_offset_in_seg) = Self::global_to_segment_offset(data_global_offset, segment_sizes)?;
                    
                    if let Ok(hashes) = Self::read_hash_section(file_pool, data_seg_idx, data_offset_in_seg) {
                        trace!("  Found {} hashes in hash section", hashes.len());
                        stored_hashes.extend(hashes);
                    }
                }
                "digest" => {
                    let data_global_offset = current_global_offset + 76;
                    let (data_seg_idx, data_offset_in_seg) = Self::global_to_segment_offset(data_global_offset, segment_sizes)?;
                    
                    if let Ok(hashes) = Self::read_digest_section(file_pool, data_seg_idx, data_offset_in_seg, section_desc.size) {
                        trace!("  Found {} hashes in digest section", hashes.len());
                        stored_hashes.extend(hashes);
                    }
                }
                "done" => {
                    segments[seg_idx].sections.push(seg_section);
                    trace!("Reached 'done' section, stopping");
                    break;
                }
                "next" => {
                    if section_desc.next_offset == current_global_offset {
                        if seg_idx + 1 < segments.len() {
                            seg_idx += 1;
                            let next_segment_start: u64 = segment_sizes.iter().take(seg_idx).sum();
                            current_global_offset = next_segment_start + 13;
                            trace!("Moving to segment {} at global offset {}", seg_idx, current_global_offset);
                            continue;
                        } else {
                            trace!("No more segments, stopping");
                            break;
                        }
                    }
                }
                _ => {}
            }
            
            segments[seg_idx].sections.push(seg_section);
            
            if section_desc.next_offset == 0 || section_desc.next_offset == current_global_offset {
                trace!("Section chain ended");
                break;
            }
            
            let segment_start: u64 = segment_sizes.iter().take(seg_idx).sum();
            current_global_offset = segment_start + section_desc.next_offset;
        }
        
        trace!("Parsed {} sections, {} chunk locations", section_count, chunk_locations.len());
        
        // If no chunk locations were found, try delta chunk scanning
        if chunk_locations.is_empty() {
            if let (Some(vol), Some(sectors_offset), Some(sectors_size)) = 
                (&volume_info, sectors_data_offset, sectors_data_size) 
            {
                trace!("No table found - attempting delta chunk scan at offset {} size {}", 
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
                    trace!("Found {} delta chunks", delta_locations.len());
                    chunk_locations = delta_locations;
                }
            }
        }
        
        Ok((segments, volume_info, chunk_locations, stored_hashes))
    }
    
    /// Scan for delta/inline chunks in sectors section
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
        
        trace!("Scanning delta chunks: sectors_offset={}, sectors_size={}, expected_chunks={}, chunk_size={}", 
                 sectors_offset, sectors_size, expected_chunks, chunk_size);
        
        for chunk_idx in 0..expected_chunks {
            if current_offset >= end_offset {
                trace!("Delta scan reached end of sectors at chunk {}", chunk_idx);
                break;
            }
            
            let local_offset = current_offset - sectors_offset + offset_in_seg;
            
            file.seek(SeekFrom::Start(local_offset))
                .map_err(|e| format!("Seek failed at offset {}: {}", local_offset, e))?;
            
            let mut header = [0u8; 4];
            file.read_exact(&mut header)
                .map_err(|e| format!("Read header failed at offset {}: {}", local_offset, e))?;
            
            let raw_size = u32::from_le_bytes(header);
            let is_compressed = (raw_size & 0x80000000) != 0;
            let data_size = (raw_size & 0x7FFFFFFF) as u64;
            
            if chunk_idx < 5 {
                trace!("  Delta chunk[{}]: offset={}, raw_size={:#x}, compressed={}, data_size={}", 
                         chunk_idx, current_offset, raw_size, is_compressed, data_size);
            }
            
            locations.push(ChunkLocation {
                segment_index: seg_idx,
                section_index: 0,
                chunk_in_table: chunk_idx,
                offset: raw_size as u64,
                base_offset: 0,
                sectors_base: current_offset,
                is_delta_chunk: true,
            });
            
            current_offset += 4 + data_size;
            
            if data_size < chunk_size as u64 && !is_compressed {
                trace!("  Warning: uncompressed chunk smaller than expected: {} < {}", data_size, chunk_size);
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
    
    /// Read chunk without caching - optimized for sequential access patterns
    pub fn read_chunk_no_cache(&mut self, chunk_index: usize) -> Result<Vec<u8>, String> {
        self.read_chunk_internal(chunk_index, false)
    }
    
    fn read_chunk_internal(&mut self, chunk_index: usize, use_cache: bool) -> Result<Vec<u8>, String> {
        // Check cache first
        if use_cache {
            if let Some(cached_data) = self.chunk_cache.get(chunk_index) {
                return Ok(Arc::try_unwrap(cached_data).unwrap_or_else(|arc| (*arc).clone()));
            }
        }
        
        let chunk_size = (self.volume.sectors_per_chunk as usize) * (self.volume.bytes_per_sector as usize);
        
        let location = match self.chunk_table.get(chunk_index) {
            Some(loc) => loc.clone(),
            None => {
                let expected_chunks = self.volume.chunk_count as usize;
                if chunk_index >= expected_chunks {
                    return Err(format!("Chunk {} beyond expected count {}", chunk_index, expected_chunks));
                }
                
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
        
        if location.offset == 0 && location.sectors_base == 0 {
            return Ok(vec![0u8; chunk_size]);
        }
        
        let segment_sizes: Vec<u64> = self.segments.iter().map(|s| s.file_size).collect();
        
        let (seg_idx, offset_in_segment, is_compressed) = if location.is_delta_chunk {
            let is_compressed = (location.offset & 0x80000000) != 0;
            let data_offset = location.sectors_base + 4;
            
            let (seg_idx, offset_in_seg) = Self::global_to_segment_offset(data_offset, &segment_sizes)
                .map_err(|e| format!("Delta chunk {}: offset {} error: {}", chunk_index, data_offset, e))?;
            
            if chunk_index < 3 {
                trace!("Delta chunk {}: sectors_base={} data_offset={} compressed={} seg={} local={}", 
                         chunk_index, location.sectors_base, data_offset, is_compressed, seg_idx, offset_in_seg);
            }
            
            (seg_idx, offset_in_seg, is_compressed)
        } else {
            let is_compressed = (location.offset & 0x80000000) != 0;
            let offset_value = (location.offset & 0x7FFFFFFF) as u64;
            
            let segment_local_offset = if location.base_offset > 0 {
                location.base_offset + offset_value
            } else {
                offset_value
            };
            
            let segment_start: u64 = segment_sizes.iter().take(location.segment_index).sum();
            let absolute_offset = segment_start + segment_local_offset;
            
            let (seg_idx, offset_in_segment) = match Self::global_to_segment_offset(absolute_offset, &segment_sizes) {
                Ok(result) => result,
                Err(e) => {
                    trace!("Chunk {}: offset={:#x} compressed={} offset_value={} segment_local={} absolute={} ERROR: {}", 
                             chunk_index, location.offset, is_compressed, offset_value, segment_local_offset, absolute_offset, e);
                    return Err(e);
                }
            };
            
            if chunk_index < 3 {
                trace!("Chunk {}: offset={:#x} compressed={} offset_value={} base_offset={} sectors_base={} absolute={} seg={} local={}", 
                         chunk_index, location.offset, is_compressed, offset_value, location.base_offset, location.sectors_base, absolute_offset, seg_idx, offset_in_segment);
            }
            
            (seg_idx, offset_in_segment, is_compressed)
        };
        
        let file = self.file_pool.get_file(self.segments[seg_idx].file_index)?;
        
        file.seek(SeekFrom::Start(offset_in_segment))
            .map_err(|e| format!("Seek to chunk {} at offset {} failed: {}", chunk_index, offset_in_segment, e))?;
        
        let mut chunk_data = if is_compressed {
            let buffered = std::io::BufReader::with_capacity(65536, file.take(chunk_size as u64 * 2));
            let mut decoder = ZlibDecoder::new(buffered);
            let mut decompressed = Vec::with_capacity(chunk_size);
            decoder.read_to_end(&mut decompressed)
                .map_err(|e| format!("Chunk {} decompression failed at offset {}: {}", chunk_index, offset_in_segment, e))?;
            decompressed
        } else {
            let mut uncompressed = vec![0u8; chunk_size];
            file.read_exact(&mut uncompressed)
                .map_err(|e| format!("Read uncompressed chunk failed: {}", e))?;
            uncompressed
        };
        
        // Truncate last chunk if needed
        let expected_chunks = self.volume.sector_count.div_ceil(self.volume.sectors_per_chunk as u64);
        if chunk_index == (expected_chunks as usize - 1) {
            let remaining_sectors = self.volume.sector_count % self.volume.sectors_per_chunk as u64;
            if remaining_sectors > 0 {
                let final_size = (remaining_sectors * self.volume.bytes_per_sector as u64) as usize;
                trace!("Last chunk {}: original size={}, remaining_sectors={}, truncating to {}", 
                         chunk_index, chunk_data.len(), remaining_sectors, final_size);
                if chunk_data.len() > final_size {
                    chunk_data.truncate(final_size);
                }
            }
        }
        
        if use_cache {
            self.chunk_cache.insert(chunk_index, chunk_data.clone());
        }
        
        Ok(chunk_data)
    }

    pub fn get_volume_info(&self) -> &VolumeSection {
        &self.volume
    }

    pub fn get_chunk_count(&self) -> usize {
        self.volume.chunk_count as usize
    }
    
    /// Get the number of chunks actually stored in the table
    pub fn get_stored_chunk_count(&self) -> usize {
        self.chunk_table.len()
    }

    // =========================================================================
    // Section Reading Helper Methods
    // =========================================================================

    fn read_section_descriptor(file: &mut File, offset: u64) -> Result<SectionDescriptor, String> {
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Seek failed: {}", e))?;
        
        let mut section_type = [0u8; 16];
        file.read_exact(&mut section_type)
            .map_err(|e| format!("Read section type failed: {}", e))?;
        
        let next_offset = read_u64_le(file)?;
        let size = read_u64_le(file)?;
        
        Ok(SectionDescriptor {
            section_type,
            next_offset,
            size,
        })
    }

    fn read_volume_section(file_pool: &mut FileIoPool, file_index: usize, offset: u64) -> Result<VolumeSection, String> {
        trace!("read_volume_section: file_index={}, offset={}", file_index, offset);
        
        let file = file_pool.get_file(file_index)?;
        
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Seek failed: {}", e))?;
        
        let mut raw_bytes = [0u8; 20];
        file.read_exact(&mut raw_bytes)
            .map_err(|e| format!("Read raw bytes failed: {}", e))?;
        trace!("Raw volume bytes: {:02x?}", &raw_bytes);
        
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Re-seek failed: {}", e))?;
        
        let _media_and_padding = read_u32_le(file)?;
        let chunk_count = read_u32_le(file)?;
        let sectors_per_chunk = read_u32_le(file)?;
        let bytes_per_sector = read_u32_le(file)?;
        let sector_count = read_u64_le(file)?;
        
        trace!("Volume: chunk_count={}, sectors_per_chunk={}, bytes_per_sector={}, sector_count={}", 
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
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Seek failed: {}", e))?;
        
        let mut header_bytes = [0u8; 24];
        file.read_exact(&mut header_bytes)
            .map_err(|e| format!("Read header failed: {}", e))?;
        
        trace!("    Raw table header bytes: {:02x?}", &header_bytes);
        
        let entry_count = u32::from_le_bytes([header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]]);
        let base_offset = u64::from_le_bytes([
            header_bytes[8], header_bytes[9], header_bytes[10], header_bytes[11],
            header_bytes[12], header_bytes[13], header_bytes[14], header_bytes[15]
        ]);
        
        let chunk_count = if entry_count > 0 {
            entry_count
        } else {
            ((size.saturating_sub(24 + 4)) / 4) as u32
        };
        
        trace!("    Table: entry_count={}, base_offset={}, using_count={}", 
                 entry_count, base_offset, chunk_count);
        
        let mut offsets = Vec::with_capacity(chunk_count as usize);
        for i in 0..chunk_count {
            let raw_offset = read_u32_le(file)? as u64;
            offsets.push(raw_offset);
            
            if i < 5 {
                let is_compressed = (raw_offset & 0x80000000) != 0;
                let offset_value = raw_offset & 0x7FFFFFFF;
                let current_pos = file.stream_position().unwrap_or(0);
                trace!("      Offset[{}] at file_pos={}: raw={:#x} compressed={} value={}", 
                         i, current_pos - 4, raw_offset, is_compressed, offset_value);
            }
        }
        
        Ok(TableSection {
            chunk_count,
            base_offset,
            offsets,
        })
    }

    /// Read hash section from EWF file (EWF1 format)
    fn read_hash_section(
        file_pool: &mut FileIoPool,
        file_index: usize,
        offset: u64,
    ) -> Result<Vec<StoredImageHash>, String> {
        let file = file_pool.get_file(file_index)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Failed to seek to hash section: {}", e))?;
        
        let mut hashes = Vec::new();
        
        let mut md5_bytes = [0u8; 16];
        if file.read_exact(&mut md5_bytes).is_ok() {
            if md5_bytes.iter().any(|&b| b != 0) {
                let md5_hash = md5_bytes.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                hashes.push(StoredImageHash {
                    algorithm: "MD5".to_string(),
                    hash: md5_hash,
                    timestamp: None,
                    source: Some("container".to_string()),
                });
            }
        }
        
        Ok(hashes)
    }

    /// Read digest section from EWF2 format
    fn read_digest_section(
        file_pool: &mut FileIoPool,
        file_index: usize,
        offset: u64,
        size: u64,
    ) -> Result<Vec<StoredImageHash>, String> {
        let file = file_pool.get_file(file_index)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Failed to seek to digest section: {}", e))?;
        
        let mut hashes = Vec::new();
        
        let mut md5_bytes = [0u8; 16];
        if file.read_exact(&mut md5_bytes).is_ok() && md5_bytes.iter().any(|&b| b != 0) {
            let md5_hash = md5_bytes.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            hashes.push(StoredImageHash {
                algorithm: "MD5".to_string(),
                hash: md5_hash,
                timestamp: None,
                source: Some("container".to_string()),
            });
        }
        
        if size >= 36 {
            let mut sha1_bytes = [0u8; 20];
            if file.read_exact(&mut sha1_bytes).is_ok() && sha1_bytes.iter().any(|&b| b != 0) {
                let sha1_hash = sha1_bytes.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                hashes.push(StoredImageHash {
                    algorithm: "SHA1".to_string(),
                    hash: sha1_hash,
                    timestamp: None,
                    source: Some("container".to_string()),
                });
            }
        }
        
        Ok(hashes)
    }
}
