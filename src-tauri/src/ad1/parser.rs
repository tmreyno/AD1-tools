//! AD1 parser implementation with Session management

use flate2::read::ZlibDecoder;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use tracing::{trace, debug, instrument};

use super::types::*;
use super::utils::*;
use crate::common::hash::{HashAlgorithm, compute_hash};

/// LRU cache entry with access counter
#[derive(Clone)]
pub(crate) struct CacheEntry {
    pub data: Arc<Vec<u8>>,
    pub access_count: u32,
}

/// AD1 parsing session - manages file handles, caching, and parsing state
pub(crate) struct Session {
    pub segment_header: SegmentHeader,
    pub logical_header: LogicalHeader,
    pub files: Vec<File>,
    pub file_sizes: Vec<u64>,
    pub item_counter: u64,
    pub root_items: Vec<Item>,
    cache: HashMap<u64, CacheEntry>,
    cache_order: Vec<u64>,
}

impl Session {
    /// Open an AD1 container and parse its structure
    #[instrument(skip_all, fields(path))]
    pub fn open(path: &str) -> Result<Self, String> {
        debug!(path, "Opening AD1 session");
        validate_input(path)?;
        let mut header_file = File::open(path)
            .map_err(|e| format!("Failed to open AD1 file '{path}': {e}"))?;
        let segment_header = read_segment_header(&mut header_file)?;
        let logical_header = read_logical_header(&mut header_file)?;
        
        debug!(
            segment_count = segment_header.segment_number,
            first_item_addr = logical_header.first_item_addr,
            "AD1 headers parsed"
        );

        let mut files = Vec::new();
        let mut file_sizes = Vec::new();
        for index in 1..=segment_header.segment_number {
            let segment_path = build_segment_path(path, index);
            trace!(index, segment_path, "Opening segment");
            let mut file = File::open(&segment_path)
                .map_err(|e| format!("Failed to open segment '{segment_path}': {e}"))?;
            let size = file
                .seek(SeekFrom::End(0))
                .map_err(|e| format!("Failed to seek segment '{segment_path}': {e}"))?;
            let data_size = size.saturating_sub(AD1_LOGICAL_MARGIN);
            file.seek(SeekFrom::Start(0))
                .map_err(|e| format!("Failed to rewind segment '{segment_path}': {e}"))?;
            files.push(file);
            file_sizes.push(data_size);
        }

        let mut session = Session {
            segment_header,
            logical_header,
            files,
            file_sizes,
            item_counter: 0,
            root_items: Vec::new(),
            cache: HashMap::with_capacity(CACHE_SIZE),
            cache_order: Vec::with_capacity(CACHE_SIZE),
        };

        let root_items = session.read_item_chain(session.logical_header.first_item_addr)?;
        debug!(root_item_count = root_items.len(), "Parsed root items");
        session.root_items = root_items;

        Ok(session)
    }

    /// Read a chain of items starting at the given offset
    pub fn read_item_chain(&mut self, offset: u64) -> Result<Vec<Item>, String> {
        let mut items = Vec::new();
        let mut next_addr = offset;
        while next_addr != 0 {
            let (item, next) = self.read_item(next_addr)?;
            items.push(item);
            next_addr = next;
        }
        Ok(items)
    }

    /// Read a single item at the given offset
    fn read_item(&mut self, offset: u64) -> Result<(Item, u64), String> {
        let next_item_addr = self.read_u64(offset)?;
        let first_child_addr = self.read_u64(offset + 0x08)?;
        let first_metadata_addr = self.read_u64(offset + 0x10)?;
        let zlib_metadata_addr = self.read_u64(offset + 0x18)?;
        let decompressed_size = self.read_u64(offset + 0x20)?;
        let item_type = self.read_u32(offset + 0x28)?;
        let name_length = self.read_u32(offset + 0x2c)? as usize;
        let name_bytes = self.read_bytes(offset + 0x30, name_length)?;
        let mut name = bytes_to_string(&name_bytes);
        name = name.replace('/', "_");

        let metadata = if first_metadata_addr != 0 {
            self.read_metadata_list(first_metadata_addr)?
        } else {
            Vec::new()
        };

        let children = if first_child_addr != 0 {
            self.read_item_chain(first_child_addr)?
        } else {
            Vec::new()
        };

        self.item_counter += 1;
        let item = Item {
            id: self.item_counter,
            name,
            item_type,
            decompressed_size,
            zlib_metadata_addr,
            metadata,
            children,
        };

        Ok((item, next_item_addr))
    }

    /// Read metadata list starting at the given offset
    fn read_metadata_list(&mut self, offset: u64) -> Result<Vec<Metadata>, String> {
        let mut list = Vec::new();
        let mut next_addr = offset;
        while next_addr != 0 {
            let meta = self.read_metadata(next_addr)?;
            next_addr = meta.next_metadata_addr;
            list.push(meta);
        }
        Ok(list)
    }

    /// Read a single metadata entry
    fn read_metadata(&mut self, offset: u64) -> Result<Metadata, String> {
        let next_metadata_addr = self.read_u64(offset)?;
        let category = self.read_u32(offset + 0x08)?;
        let key = self.read_u32(offset + 0x0c)?;
        let data_length = self.read_u32(offset + 0x10)? as usize;
        let data = self.read_bytes(offset + 0x14, data_length)?;

        Ok(Metadata {
            next_metadata_addr,
            category,
            key,
            data,
        })
    }

    /// Read u32 at offset
    pub fn read_u32(&mut self, offset: u64) -> Result<u32, String> {
        let bytes = self.read_bytes(offset, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read u64 at offset
    pub fn read_u64(&mut self, offset: u64) -> Result<u64, String> {
        let bytes = self.read_bytes(offset, 8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read bytes at offset
    pub fn read_bytes(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, String> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; length];
        self.read_into(offset, &mut buf)?;
        Ok(buf)
    }

    /// Read into buffer at offset (handles multi-segment reads)
    fn read_into(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        if buf.is_empty() {
            return Ok(());
        }

        let seg_span = segment_span(self.segment_header.fragments_size);
        if seg_span == 0 {
            return Err("Invalid AD1 fragment size".to_string());
        }
        let mut remaining = buf.len() as u64;
        let mut buf_cursor = 0usize;
        let mut file_cursor = (offset / seg_span) as usize;
        let mut data_cursor = offset - (seg_span * file_cursor as u64);

        while remaining > 0 {
            let file_size = self
                .file_sizes
                .get(file_cursor)
                .copied()
                .ok_or_else(|| "AD1 offset out of range".to_string())?;
            let mut to_read = remaining;
            if data_cursor + to_read > file_size {
                to_read = file_size.saturating_sub(data_cursor);
            }
            if to_read == 0 {
                return Err("AD1 offset out of range".to_string());
            }

            let file = self
                .files
                .get_mut(file_cursor)
                .ok_or_else(|| "AD1 segment index out of range".to_string())?;
            file.seek(SeekFrom::Start(data_cursor + AD1_LOGICAL_MARGIN))
                .map_err(|e| format!("Failed to seek segment data: {e}"))?;
            file.read_exact(&mut buf[buf_cursor..buf_cursor + to_read as usize])
                .map_err(|e| format!("Failed to read segment data: {e}"))?;

            buf_cursor += to_read as usize;
            remaining -= to_read;
            data_cursor = 0;
            file_cursor += 1;
        }

        Ok(())
    }

    /// Read and decompress file data for an item
    pub fn read_file_data(&mut self, item: &Item) -> Result<Arc<Vec<u8>>, String> {
        if item.decompressed_size == 0 {
            return Ok(Arc::new(Vec::new()));
        }
        if let Some(data) = self.search_cache(item.id) {
            return Ok(data);
        }
        if item.zlib_metadata_addr == 0 {
            return Err("Missing zlib metadata address".to_string());
        }

        let chunk_count = self.read_u64(item.zlib_metadata_addr)?;
        let mut addresses = Vec::with_capacity(chunk_count as usize + 1);
        for index in 0..=chunk_count {
            let addr = self.read_u64(item.zlib_metadata_addr + ((index + 1) * 0x08))?;
            addresses.push(addr);
        }

        // For small files (< 4 chunks), use sequential decompression
        // For larger files, use parallel decompression
        let data = if chunk_count < 4 {
            self.decompress_sequential(&addresses, item.decompressed_size as usize)?
        } else {
            self.decompress_parallel(&addresses, item.decompressed_size as usize)?
        };

        let data = Arc::new(data);
        self.cache_data(item.id, data.clone());
        Ok(data)
    }

    /// Sequential decompression for small files
    fn decompress_sequential(&mut self, addresses: &[u64], decompressed_size: usize) -> Result<Vec<u8>, String> {
        let chunk_count = addresses.len() - 1;
        let mut output = vec![0u8; decompressed_size];
        let mut data_index = 0usize;
        
        for index in 0..chunk_count {
            let start = addresses[index];
            let end = addresses[index + 1];
            let compressed_len = end.saturating_sub(start) as usize;
            if compressed_len == 0 {
                continue;
            }
            let compressed = self.read_bytes(start, compressed_len)?;
            let mut decoder = ZlibDecoder::new(&compressed[..]);
            let mut chunk = Vec::new();
            decoder
                .read_to_end(&mut chunk)
                .map_err(|e| format!("Zlib inflate error: {e}"))?;
            let end_index = (data_index + chunk.len()).min(output.len());
            output[data_index..end_index].copy_from_slice(&chunk[..end_index - data_index]);
            data_index = end_index;
        }
        
        Ok(output)
    }

    /// Parallel decompression for large files
    fn decompress_parallel(&mut self, addresses: &[u64], decompressed_size: usize) -> Result<Vec<u8>, String> {
        let chunk_count = addresses.len() - 1;
        
        // Pre-read all compressed chunks sequentially (I/O bound)
        let mut compressed_chunks: Vec<(usize, Vec<u8>)> = Vec::with_capacity(chunk_count);
        for index in 0..chunk_count {
            let start = addresses[index];
            let end = addresses[index + 1];
            let compressed_len = end.saturating_sub(start) as usize;
            if compressed_len == 0 {
                continue;
            }
            let compressed = self.read_bytes(start, compressed_len)?;
            compressed_chunks.push((index, compressed));
        }
        
        // Decompress in parallel (CPU bound)
        let decompressed_chunks: Vec<Result<(usize, Vec<u8>), String>> = compressed_chunks
            .par_iter()
            .map(|(index, compressed)| {
                let mut decoder = ZlibDecoder::new(&compressed[..]);
                let mut chunk = Vec::new();
                decoder
                    .read_to_end(&mut chunk)
                    .map_err(|e| format!("Zlib inflate error: {e}"))?;
                Ok((*index, chunk))
            })
            .collect();
        
        // Assemble output in order
        let mut output = vec![0u8; decompressed_size];
        let mut data_index = 0usize;
        
        // Sort by index to maintain order
        let mut sorted_chunks: Vec<(usize, Vec<u8>)> = Vec::with_capacity(decompressed_chunks.len());
        for result in decompressed_chunks {
            sorted_chunks.push(result?);
        }
        sorted_chunks.sort_by_key(|(idx, _)| *idx);
        
        for (_, chunk) in sorted_chunks {
            let end_index = (data_index + chunk.len()).min(output.len());
            output[data_index..end_index].copy_from_slice(&chunk[..end_index - data_index]);
            data_index = end_index;
        }
        
        Ok(output)
    }

    /// O(1) cache lookup using HashMap
    fn search_cache(&mut self, item_id: u64) -> Option<Arc<Vec<u8>>> {
        if let Some(entry) = self.cache.get_mut(&item_id) {
            entry.access_count = entry.access_count.saturating_add(1);
            return Some(entry.data.clone());
        }
        None
    }

    /// LRU cache insertion with eviction
    fn cache_data(&mut self, item_id: u64, data: Arc<Vec<u8>>) {
        if self.cache.contains_key(&item_id) {
            return;
        }
        
        // Evict oldest entry if cache is full
        if self.cache.len() >= CACHE_SIZE {
            if let Some(oldest_id) = self.cache_order.first().copied() {
                self.cache.remove(&oldest_id);
                self.cache_order.remove(0);
            }
        }
        
        self.cache.insert(item_id, CacheEntry {
            data,
            access_count: 1,
        });
        self.cache_order.push(item_id);
    }

    /// Verify item hash with progress callback
    pub fn verify_item_with_progress<F>(
        &mut self,
        item: &Item,
        parent_path: &str,
        algorithm: HashAlgorithm,
        out: &mut Vec<VerifyEntry>,
        current: &mut usize,
        total: usize,
        progress_callback: &mut F,
    ) -> Result<(), String>
    where
        F: FnMut(usize, usize)
    {
        let path = join_path(parent_path, &item.name);
        if item.item_type != AD1_FOLDER_SIGNATURE {
            let stored = match algorithm {
                HashAlgorithm::Md5 => find_hash(&item.metadata, MD5_HASH),
                HashAlgorithm::Sha1 => find_hash(&item.metadata, SHA1_HASH),
                HashAlgorithm::Sha256 | HashAlgorithm::Sha512 | 
                HashAlgorithm::Blake3 | HashAlgorithm::Blake2 |
                HashAlgorithm::Xxh3 | HashAlgorithm::Xxh64 | HashAlgorithm::Crc32 => None,
            };
            
            let data = self.read_file_data(item)?;
            let computed = compute_hash(&data, algorithm);
            
            let (status, stored_for_output) = match &stored {
                Some(stored_hash) => {
                    // Compare hashes case-insensitively (both should be lowercase, but be safe)
                    let matches = stored_hash.eq_ignore_ascii_case(&computed);
                    if matches {
                        ("ok", Some(stored_hash.clone()))
                    } else {
                        debug!(
                            path = %path,
                            stored = %stored_hash,
                            computed = %computed,
                            size = item.decompressed_size,
                            "Hash mismatch"
                        );
                        ("nok", Some(stored_hash.clone()))
                    }
                }
                None => {
                    trace!(path = %path, "No stored hash, computed only");
                    ("computed", None)
                }
            };

            out.push(VerifyEntry {
                path: path.clone(),
                status: status.to_string(),
                algorithm: Some(algorithm.name().to_string()),
                computed: Some(computed),
                stored: stored_for_output,
                size: Some(item.decompressed_size),
            });
            
            *current += 1;
            progress_callback(*current, total);
        }

        for child in &item.children {
            self.verify_item_with_progress(child, &path, algorithm, out, current, total, progress_callback)?;
        }

        Ok(())
    }

    /// Extract item with progress callback
    pub fn extract_item_with_progress<F>(
        &mut self,
        item: &Item,
        output_dir: &Path,
        current: &mut usize,
        total: usize,
        progress_callback: &mut F,
    ) -> Result<(), String>
    where
        F: FnMut(usize, usize)
    {
        let item_path = output_dir.join(&item.name);
        if item.item_type == AD1_FOLDER_SIGNATURE {
            fs::create_dir_all(&item_path)
                .map_err(|e| format!("Failed to create directory {:?}: {e}", item_path))?;
        } else if item.item_type == 0 {
            if let Some(parent) = item_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!("Failed to create directory {:?}: {e}", parent)
                })?;
            }
            let data = self.read_file_data(item)?;
            let mut file = File::create(&item_path)
                .map_err(|e| format!("Failed to create file {:?}: {e}", item_path))?;
            file.write_all(&data)
                .map_err(|e| format!("Failed to write file {:?}: {e}", item_path))?;
            
            *current += 1;
            progress_callback(*current, total);
        }

        for child in &item.children {
            self.extract_item_with_progress(child, &item_path, current, total, progress_callback)?;
        }

        apply_metadata(&item_path, &item.metadata)?;
        Ok(())
    }
}
