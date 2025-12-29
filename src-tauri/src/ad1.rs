use chrono::{Local, NaiveDateTime, TimeZone};
use filetime::FileTime;
use flate2::read::ZlibDecoder;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use crate::common::hash::{HashAlgorithm, compute_hash};

const AD1_SIGNATURE: &[u8; 15] = b"ADSEGMENTEDFILE";
const AD1_LOGICAL_MARGIN: u64 = 512;
const AD1_FOLDER_SIGNATURE: u32 = 0x05;
const CACHE_SIZE: usize = 100;  // Increased from 25 for better cache hit rate
const SEGMENT_BLOCK_SIZE: u64 = 65_536;

const HASH_INFO: u32 = 0x01;
const TIMESTAMP: u32 = 0x05;

const MD5_HASH: u32 = 0x5001;
const SHA1_HASH: u32 = 0x5002;

const ACCESS: u32 = 0x07;
const MODIFIED: u32 = 0x08;

#[derive(Serialize)]
pub struct SegmentHeaderInfo {
    pub signature: String,
    pub segment_index: u32,
    pub segment_number: u32,
    pub fragments_size: u32,
    pub header_size: u32,
}

#[derive(Serialize)]
pub struct LogicalHeaderInfo {
    pub signature: String,
    pub image_version: u32,
    pub zlib_chunk_size: u32,
    pub logical_metadata_addr: u64,
    pub first_item_addr: u64,
    pub data_source_name_length: u32,
    pub ad_signature: String,
    pub data_source_name_addr: u64,
    pub attrguid_footer_addr: u64,
    pub locsguid_footer_addr: u64,
    pub data_source_name: String,
}

#[derive(Serialize)]
pub struct TreeEntry {
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub item_type: u32,
}

#[derive(Serialize)]
pub struct VerifyEntry {
    pub path: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct Ad1Info {
    pub segment: SegmentHeaderInfo,
    pub logical: LogicalHeaderInfo,
    pub item_count: u64,
    pub tree: Option<Vec<TreeEntry>>,
}

#[derive(Clone)]
struct SegmentHeader {
    signature: [u8; 16],
    segment_index: u32,
    segment_number: u32,
    fragments_size: u32,
    header_size: u32,
}

#[derive(Clone)]
struct LogicalHeader {
    signature: [u8; 16],
    image_version: u32,
    zlib_chunk_size: u32,
    logical_metadata_addr: u64,
    first_item_addr: u64,
    data_source_name_length: u32,
    ad_signature: [u8; 4],
    data_source_name_addr: u64,
    attrguid_footer_addr: u64,
    locsguid_footer_addr: u64,
    data_source_name: String,
}

#[derive(Clone)]
struct Metadata {
    next_metadata_addr: u64,
    category: u32,
    key: u32,
    data: Vec<u8>,
}

#[derive(Clone)]
struct Item {
    id: u64,
    name: String,
    item_type: u32,
    decompressed_size: u64,
    zlib_metadata_addr: u64,
    metadata: Vec<Metadata>,
    children: Vec<Item>,
}

/// LRU cache entry with access counter
#[derive(Clone)]
struct CacheEntry {
    data: Arc<Vec<u8>>,
    access_count: u32,
}

struct Session {
    segment_header: SegmentHeader,
    logical_header: LogicalHeader,
    files: Vec<File>,
    file_sizes: Vec<u64>,
    item_counter: u64,
    root_items: Vec<Item>,
    cache: HashMap<u64, CacheEntry>,  // item_id -> cached data
    cache_order: Vec<u64>,  // LRU order tracking
}

pub fn info(path: &str, include_tree: bool) -> Result<Ad1Info, String> {
    let session = Session::open(path)?;
    let segment_info = segment_header_info(&session.segment_header);
    let logical_info = logical_header_info(&session.logical_header);

    let tree = if include_tree {
        let mut entries = Vec::new();
        collect_tree(&session.root_items, "", &mut entries);
        Some(entries)
    } else {
        None
    };

    Ok(Ad1Info {
        segment: segment_info,
        logical: logical_info,
        item_count: session.item_counter,
        tree,
    })
}

pub fn verify(path: &str, algorithm: &str) -> Result<Vec<VerifyEntry>, String> {
    let mut session = Session::open(path)?;
    let algo = HashAlgorithm::from_str(algorithm)?;
    let mut results = Vec::new();
    let root_items = session.root_items.clone();
    for item in &root_items {
        session.verify_item(item, "", algo, &mut results)?;
    }
    Ok(results)
}

pub fn extract(path: &str, output_dir: &str) -> Result<(), String> {
    if output_dir.trim().is_empty() {
        return Err("Output directory is required".to_string());
    }
    let mut session = Session::open(path)?;
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create output directory: {e}"))?;
    let root_items = session.root_items.clone();
    for item in &root_items {
        session.extract_item(item, Path::new(output_dir))?;
    }
    Ok(())
}

pub fn is_ad1(path: &str) -> Result<bool, String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("Input file not found: {path}"));
    }
    let mut file = File::open(path_obj)
        .map_err(|e| format!("Failed to open input file: {e}"))?;
    let mut signature = [0u8; 16];
    file.read_exact(&mut signature)
        .map_err(|e| format!("Failed to read file signature: {e}"))?;
    Ok(&signature[..15] == AD1_SIGNATURE)
}

impl Session {
    fn open(path: &str) -> Result<Self, String> {
        validate_input(path)?;
        let mut header_file = File::open(path)
            .map_err(|e| format!("Failed to open AD1 file '{path}': {e}"))?;
        let segment_header = read_segment_header(&mut header_file)?;
        let logical_header = read_logical_header(&mut header_file)?;

        let mut files = Vec::new();
        let mut file_sizes = Vec::new();
        for index in 1..=segment_header.segment_number {
            let segment_path = build_segment_path(path, index);
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
        session.root_items = root_items;

        Ok(session)
    }

    fn read_item_chain(&mut self, offset: u64) -> Result<Vec<Item>, String> {
        let mut items = Vec::new();
        let mut next_addr = offset;
        while next_addr != 0 {
            let (item, next) = self.read_item(next_addr)?;
            items.push(item);
            next_addr = next;
        }
        Ok(items)
    }

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

    fn read_u32(&mut self, offset: u64) -> Result<u32, String> {
        let bytes = self.read_bytes(offset, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self, offset: u64) -> Result<u64, String> {
        let bytes = self.read_bytes(offset, 8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_bytes(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, String> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; length];
        self.read_into(offset, &mut buf)?;
        Ok(buf)
    }

    fn read_into(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        if buf.is_empty() {
            return Ok(());
        }

        let segment_span = segment_span(self.segment_header.fragments_size);
        if segment_span == 0 {
            return Err("Invalid AD1 fragment size".to_string());
        }
        let mut remaining = buf.len() as u64;
        let mut buf_cursor = 0usize;
        let mut file_cursor = (offset / segment_span) as usize;
        let mut data_cursor = offset - (segment_span * file_cursor as u64);

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

    fn read_file_data(&mut self, item: &Item) -> Result<Arc<Vec<u8>>, String> {
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
        // If already in cache, update
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
        
        // Insert new entry
        self.cache.insert(item_id, CacheEntry {
            data,
            access_count: 1,
        });
        self.cache_order.push(item_id);
    }

    fn verify_item(
        &mut self,
        item: &Item,
        parent_path: &str,
        algorithm: HashAlgorithm,
        out: &mut Vec<VerifyEntry>,
    ) -> Result<(), String> {
        let path = join_path(parent_path, &item.name);
        if item.item_type != AD1_FOLDER_SIGNATURE {
            // For MD5/SHA1, compare against stored hash in AD1 metadata
            // For other algorithms, just compute and report (no stored hash to compare)
            let stored = match algorithm {
                HashAlgorithm::Md5 => find_hash(&item.metadata, MD5_HASH),
                HashAlgorithm::Sha1 => find_hash(&item.metadata, SHA1_HASH),
                // AD1 only stores MD5 and SHA1, other algorithms compute-only
                HashAlgorithm::Sha256 | HashAlgorithm::Sha512 | 
                HashAlgorithm::Blake3 | HashAlgorithm::Blake2 => None,
            };
            
            let data = self.read_file_data(item)?;
            let computed = compute_hash(&data, algorithm);
            
            let status = match stored {
                Some(stored_hash) => {
                    if stored_hash == computed {
                        "ok"
                    } else {
                        "nok"
                    }
                }
                None => {
                    // No stored hash - for non-MD5/SHA1 algorithms, report computed hash
                    "computed"
                }
            };

            out.push(VerifyEntry {
                path: path.clone(),
                status: status.to_string(),
            });
        }

        for child in &item.children {
            self.verify_item(child, &path, algorithm, out)?;
        }

        Ok(())
    }

    fn extract_item(&mut self, item: &Item, output_dir: &Path) -> Result<(), String> {
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
        }

        for child in &item.children {
            self.extract_item(child, &item_path)?;
        }

        apply_metadata(&item_path, &item.metadata)?;
        Ok(())
    }
}

fn apply_metadata(path: &Path, metadata: &[Metadata]) -> Result<(), String> {
    let mut access_time = None;
    let mut modified_time = None;

    for meta in metadata {
        if meta.category != TIMESTAMP {
            continue;
        }
        let value = metadata_string(&meta.data);
        match meta.key {
            ACCESS => access_time = parse_timestamp(&value),
            MODIFIED => modified_time = parse_timestamp(&value),
            _ => {}
        }
    }

    if access_time.is_none() && modified_time.is_none() {
        return Ok(());
    }

    let now = FileTime::from_system_time(SystemTime::now());
    let atime = access_time.unwrap_or(now);
    let mtime = modified_time.unwrap_or(atime);
    filetime::set_file_times(path, atime, mtime)
        .map_err(|e| format!("Failed to set file times for {:?}: {e}", path))?;
    Ok(())
}

fn parse_timestamp(value: &str) -> Option<FileTime> {
    let trimmed = value.trim_matches('\0').trim();
    if trimmed.len() < 15 {
        return None;
    }
    let parsed = NaiveDateTime::parse_from_str(trimmed, "%Y%m%dT%H%M%S").ok()?;
    let local = Local
        .from_local_datetime(&parsed)
        .single()
        .unwrap_or_else(|| Local.from_utc_datetime(&parsed));
    Some(FileTime::from_unix_time(local.timestamp(), 0))
}

fn find_hash(metadata: &[Metadata], key: u32) -> Option<String> {
    metadata
        .iter()
        .find(|meta| meta.category == HASH_INFO && meta.key == key)
        .map(|meta| metadata_string(&meta.data))
        .map(|value| value.to_lowercase())
}

fn collect_tree(items: &[Item], parent_path: &str, out: &mut Vec<TreeEntry>) {
    for item in items {
        let path = join_path(parent_path, &item.name);
        let is_dir = item.item_type == AD1_FOLDER_SIGNATURE;
        let size = if is_dir { 0 } else { item.decompressed_size };
        out.push(TreeEntry {
            path: path.clone(),
            is_dir,
            size,
            item_type: item.item_type,
        });
        collect_tree(&item.children, &path, out);
    }
}

fn segment_header_info(header: &SegmentHeader) -> SegmentHeaderInfo {
    SegmentHeaderInfo {
        signature: bytes_to_string(&header.signature),
        segment_index: header.segment_index,
        segment_number: header.segment_number,
        fragments_size: header.fragments_size,
        header_size: header.header_size,
    }
}

fn logical_header_info(header: &LogicalHeader) -> LogicalHeaderInfo {
    LogicalHeaderInfo {
        signature: bytes_to_string(&header.signature),
        image_version: header.image_version,
        zlib_chunk_size: header.zlib_chunk_size,
        logical_metadata_addr: header.logical_metadata_addr,
        first_item_addr: header.first_item_addr,
        data_source_name_length: header.data_source_name_length,
        ad_signature: bytes_to_string(&header.ad_signature),
        data_source_name_addr: header.data_source_name_addr,
        attrguid_footer_addr: header.attrguid_footer_addr,
        locsguid_footer_addr: header.locsguid_footer_addr,
        data_source_name: header.data_source_name.clone(),
    }
}

fn segment_span(fragments_size: u32) -> u64 {
    (fragments_size as u64 * SEGMENT_BLOCK_SIZE).saturating_sub(AD1_LOGICAL_MARGIN)
}

fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn metadata_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else if name.is_empty() {
        parent.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn validate_input(path: &str) -> Result<(), String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("Input file not found: {path}"));
    }

    let mut file = File::open(path_obj)
        .map_err(|e| format!("Failed to open input file: {e}"))?;
    let mut signature = [0u8; 16];
    file.read_exact(&mut signature)
        .map_err(|e| format!("Failed to read file signature: {e}"))?;
    if &signature[..15] != AD1_SIGNATURE {
        return Err("File is not an AD1 segmented image".to_string());
    }

    let segment_count = read_u32_at(&mut file, 0x1c)?;
    if segment_count == 0 {
        return Err("Invalid AD1 segment count".to_string());
    }

    for index in 1..=segment_count {
        let segment_path = build_segment_path(path, index);
        if !Path::new(&segment_path).exists() {
            return Err(format!("Missing AD1 segment: {segment_path}"));
        }
    }

    Ok(())
}

fn read_u32_at(file: &mut File, offset: u64) -> Result<u32, String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek input file: {e}"))?;
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read input file: {e}"))?;
    Ok(u32::from_le_bytes(buf))
}

fn build_segment_path(base: &str, index: u32) -> String {
    if base.is_empty() {
        return base.to_string();
    }
    let mut out = base.to_string();
    out.pop();
    out.push_str(&index.to_string());
    out
}

fn read_segment_header(file: &mut File) -> Result<SegmentHeader, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Failed to seek segment header: {e}"))?;
    let mut signature = [0u8; 16];
    file.read_exact(&mut signature)
        .map_err(|e| format!("Failed to read segment signature: {e}"))?;
    if &signature[..15] != AD1_SIGNATURE {
        return Err("File is not of AD1 format".to_string());
    }

    Ok(SegmentHeader {
        signature,
        segment_index: read_u32_at(file, 0x18)?,
        segment_number: read_u32_at(file, 0x1c)?,
        fragments_size: read_u32_at(file, 0x22)?,
        header_size: read_u32_at(file, 0x28)?,
    })
}

fn read_logical_header(file: &mut File) -> Result<LogicalHeader, String> {
    let signature = read_string_at(file, AD1_LOGICAL_MARGIN, 15)?;
    let image_version = read_u32_at(file, 0x210)?;
    let zlib_chunk_size = read_u32_at(file, 0x218)?;
    let logical_metadata_addr = read_u64_at(file, 0x21c)?;
    let first_item_addr = read_u64_at(file, 0x224)?;
    let data_source_name_length = read_u32_at(file, 0x22c)?;
    let ad_signature = read_string_at(file, 0x230, 3)?;
    let data_source_name_addr = read_u64_at(file, 0x234)?;
    let attrguid_footer_addr = read_u64_at(file, 0x23c)?;
    let locsguid_footer_addr = read_u64_at(file, 0x24c)?;
    let data_source_name = read_string_at(file, 0x25c, data_source_name_length as usize)?;

    Ok(LogicalHeader {
        signature: copy_into_array(&signature, 16)?,
        image_version,
        zlib_chunk_size,
        logical_metadata_addr,
        first_item_addr,
        data_source_name_length,
        ad_signature: copy_into_array(&ad_signature, 4)?,
        data_source_name_addr,
        attrguid_footer_addr,
        locsguid_footer_addr,
        data_source_name,
    })
}

fn read_string_at(file: &mut File, offset: u64, length: usize) -> Result<String, String> {
    if length == 0 {
        return Ok(String::new());
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek input file: {e}"))?;
    let mut buf = vec![0u8; length];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read input file: {e}"))?;
    Ok(bytes_to_string(&buf))
}

fn read_u64_at(file: &mut File, offset: u64) -> Result<u64, String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Failed to seek input file: {e}"))?;
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf)
        .map_err(|e| format!("Failed to read input file: {e}"))?;
    Ok(u64::from_le_bytes(buf))
}

fn copy_into_array<const N: usize>(value: &str, max_len: usize) -> Result<[u8; N], String> {
    let mut buf = [0u8; N];
    let bytes = value.as_bytes();
    let len = bytes.len().min(max_len).min(N);
    buf[..len].copy_from_slice(&bytes[..len]);
    Ok(buf)
}

// Hash algorithm and compute_hash now provided by crate::common::hash
