//! LRU Chunk Cache for E01 handle (like libfcache)

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// Chunk cache with LRU eviction
/// Uses Arc to avoid cloning large data buffers
pub(crate) struct ChunkCache {
    cache: HashMap<usize, Arc<Vec<u8>>>,
    lru_queue: VecDeque<usize>,
    max_entries: usize,
}

impl ChunkCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: HashMap::new(),
            lru_queue: VecDeque::new(),
            max_entries,
        }
    }

    pub fn get(&mut self, chunk_index: usize) -> Option<Arc<Vec<u8>>> {
        if let Some(data) = self.cache.get(&chunk_index) {
            // Move to front of LRU
            self.lru_queue.retain(|&x| x != chunk_index);
            self.lru_queue.push_front(chunk_index);
            return Some(Arc::clone(data));  // Cheap Arc clone, not data clone
        }
        None
    }

    pub fn insert(&mut self, chunk_index: usize, data: Vec<u8>) {
        // Remove oldest if at capacity
        if self.cache.len() >= self.max_entries {
            if let Some(old_index) = self.lru_queue.pop_back() {
                self.cache.remove(&old_index);
            }
        }

        self.cache.insert(chunk_index, Arc::new(data));
        self.lru_queue.push_front(chunk_index);
    }
}
