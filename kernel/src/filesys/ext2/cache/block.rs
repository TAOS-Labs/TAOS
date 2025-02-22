use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use spin::Mutex;

use super::{
    super::block_io::BlockIO, Cache, CacheEntry, CacheError, CacheResult, CacheStats,
    CacheableItem, Clock, MonotonicClock,
};

/// A cached block with its data and metadata
#[derive(Clone)]
pub struct CachedBlock {
    data: Vec<u8>,
    dirty: bool,
}

impl CachedBlock {
    fn new(size: usize) -> Self {
        Self {
            data: vec![0; size],
            dirty: false,
        }
    }

    /// Get a reference to the block's data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the block's data
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.mark_dirty();
        &mut self.data
    }
}

impl CacheableItem for CachedBlock {
    fn is_dirty(&self) -> bool {
        self.dirty
    }

    fn mark_clean(&mut self) {
        self.dirty = false;
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }
}

/// Block cache implementation
pub struct BlockCache {
    // The underlying block device
    device: Arc<dyn BlockIO>,

    // Cache entries mapped by block number
    entries: Mutex<BTreeMap<u32, CacheEntry<CachedBlock>>>,

    // Maximum number of cached blocks
    capacity: usize,

    // Cache statistics
    stats: Mutex<CacheStats>,

    // Clock for entry aging
    clock: MonotonicClock,
}

impl BlockCache {
    /// Create a new block cache
    ///
    /// # Arguments
    /// * `device` - The block device to cache
    /// * `capacity` - Maximum number of blocks to cache
    pub fn new(device: Arc<dyn BlockIO>, capacity: usize) -> Self {
        Self {
            device,
            entries: Mutex::new(BTreeMap::new()),
            capacity,
            stats: Mutex::default(),
            clock: MonotonicClock::default(),
        }
    }

    /// Find the least recently used entry
    fn find_lru_entry(&self, entries: &mut BTreeMap<u32, CacheEntry<CachedBlock>>) -> Option<u32> {
        entries
            .iter()
            .min_by_key(|(_, entry)| (entry.last_access, entry.access_count))
            .map(|(block, _)| *block)
    }

    /// Load a block from the device
    fn load_block(&self, block: u32) -> CacheResult<CachedBlock> {
        let mut cached = CachedBlock::new(self.device.block_size() as usize);

        self.device
            .read_block(block, &mut cached.data)
            .map_err(|_| CacheError::LoadError)?;

        Ok(cached)
    }

    /// Write a block back to the device
    fn write_block(&self, block: u32, cached: &CachedBlock) -> CacheResult<()> {
        if !cached.is_dirty() {
            return Ok(());
        }

        self.device
            .write_block(block, &cached.data)
            .map_err(|_| CacheError::WriteError)?;

        Ok(())
    }

    /// Evict entries if cache is full
    fn evict_if_needed(
        &self,
        entries: &mut BTreeMap<u32, CacheEntry<CachedBlock>>,
    ) -> CacheResult<()> {
        if entries.len() < self.capacity {
            return Ok(());
        }

        if let Some(block) = self.find_lru_entry(entries) {
            let entry = entries.remove(&block).unwrap();

            // Write back if dirty
            if entry.value.lock().is_dirty() {
                self.write_block(block, &entry.value.lock())?;
                self.stats.lock().writebacks += 1;
            }

            self.stats.lock().evictions += 1;
            Ok(())
        } else {
            Err(CacheError::CacheFull)
        }
    }
}

impl Cache<u32, CachedBlock> for BlockCache {
    fn get(&self, block: u32) -> CacheResult<Arc<Mutex<CachedBlock>>> {
        let mut entries = self.entries.lock();
        let now = self.clock.now();

        // Check if block is cached
        if let Some(entry) = entries.get_mut(&block) {
            entry.touch(now);
            self.stats.lock().hits += 1;
            return Ok(Arc::clone(&entry.value));
        }

        // Need to load block
        self.stats.lock().misses += 1;

        // Evict if needed
        self.evict_if_needed(&mut entries)?;

        // Load and cache block
        let cached = self.load_block(block)?;
        let entry = CacheEntry::new(cached);
        let value = Arc::clone(&entry.value);
        entries.insert(block, entry);

        Ok(value)
    }

    fn insert(&self, block: u32, cached: CachedBlock) -> CacheResult<()> {
        let mut entries = self.entries.lock();

        // Evict if needed
        self.evict_if_needed(&mut entries)?;

        // Add new entry
        entries.insert(block, CacheEntry::new(cached));
        Ok(())
    }

    fn remove(&self, block: &u32) -> CacheResult<()> {
        let mut entries = self.entries.lock();

        if let Some(entry) = entries.remove(block) {
            // Write back if dirty
            if entry.value.lock().is_dirty() {
                self.write_block(*block, &entry.value.lock())?;
                self.stats.lock().writebacks += 1;
            }
        }

        Ok(())
    }

    fn clear(&self) -> CacheResult<()> {
        let mut entries = self.entries.lock();

        // Write back all dirty blocks
        for (block, entry) in entries.iter() {
            if entry.value.lock().is_dirty() {
                self.write_block(*block, &entry.value.lock())?;
                self.stats.lock().writebacks += 1;
            }
        }

        entries.clear();
        Ok(())
    }

    fn stats(&self) -> CacheStats {
        self.stats.lock().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    // Mock block device for testing
    struct MockDevice {
        block_size: u32,
        blocks: Mutex<BTreeMap<u32, Vec<u8>>>,
    }

    impl MockDevice {
        fn new(block_size: u32) -> Self {
            Self {
                block_size,
                blocks: Mutex::new(BTreeMap::new()),
            }
        }
    }

    impl BlockIO for MockDevice {
        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn size_in_bytes(&self) -> u32 {
            u32::MAX
        }

        unsafe fn read_block(&self, block: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
            let blocks = self.blocks.lock();
            if let Some(data) = blocks.get(&block) {
                buffer.copy_from_slice(data);
                Ok(())
            } else {
                buffer.fill(0);
                Ok(())
            }
        }

        unsafe fn write_block(&mut self, block: u32, buffer: &[u8]) -> Result<(), BlockError> {
            let mut blocks = self.blocks.lock();
            blocks.insert(block, buffer.to_vec());
            Ok(())
        }
    }

    #[test]
    fn test_block_cache() {
        let device = Arc::new(MockDevice::new(512));
        let cache = BlockCache::new(Arc::clone(&device), 2);

        // Test reading uncached block
        let block = cache.get(0).unwrap();
        assert!(!block.lock().is_dirty());

        // Test modifying block
        block.lock().data_mut()[0] = 42;
        assert!(block.lock().is_dirty());

        // Test eviction
        let _block1 = cache.get(1).unwrap();
        let _block2 = cache.get(2).unwrap(); // Should evict block 0

        // Stats should show hits and misses
        let stats = cache.stats();
        assert!(stats.hits > 0);
        assert!(stats.misses > 0);
    }
}
