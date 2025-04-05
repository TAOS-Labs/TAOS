use alloc::{collections::BTreeMap, sync::Arc};
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use super::{
    super::{
        block_io::BlockIO,
        structures::{BlockGroupDescriptor, Inode, Superblock},
    },
    Cache, CacheEntry, CacheError, CacheResult, CacheStats, CacheableItem, Clock, MonotonicClock,
};

/// Cached inode with its metadata
#[derive(Clone)]
pub struct CachedInode {
    /// The raw inode data
    inode: Inode,
    /// Number of references to this inode
    ref_count: Arc<AtomicU32>,
    /// Whether the inode needs to be written back
    dirty: bool,
    /// Inode number (for convenience)
    #[allow(dead_code)]
    number: u32,
}

impl CachedInode {
    pub fn new(inode: Inode, number: u32) -> Self {
        Self {
            inode,
            ref_count: Arc::new(AtomicU32::new(1)),
            dirty: false,
            number,
        }
    }

    /// Get a reference to the underlying inode
    pub fn inode(&self) -> &Inode {
        &self.inode
    }

    /// Get a mutable reference to the underlying inode
    pub fn inode_mut(&mut self) -> &mut Inode {
        self.mark_dirty();
        &mut self.inode
    }

    /// Get the reference count
    pub fn ref_count(&self) -> u32 {
        self.ref_count.load(Ordering::Relaxed)
    }

    /// Increment reference count
    pub fn inc_ref(&self) {
        self.ref_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement reference count
    pub fn dec_ref(&self) -> u32 {
        self.ref_count.fetch_sub(1, Ordering::Relaxed)
    }
}

impl CacheableItem for CachedInode {
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

/// Storage for inode location calculations
pub struct InodeLocation {
    /// Block group containing this inode
    pub block_group: u32,
    /// Index within the inode table
    pub index: u32,
    /// Block containing this inode
    pub block: u32,
    /// Offset within the block
    pub offset: u32,
}

/// Inode cache implementation
pub struct InodeCache {
    /// The underlying block device
    #[allow(dead_code)]
    device: Arc<dyn BlockIO>,
    /// Superblock reference
    superblock: Arc<Superblock>,
    /// Block group descriptors
    bgdt: Arc<[BlockGroupDescriptor]>,
    /// Block cache reference
    block_cache: Arc<dyn Cache<u32, super::block::CachedBlock>>,
    /// Cache entries mapped by inode number
    entries: Mutex<BTreeMap<u32, CacheEntry<CachedInode>>>,
    /// Maximum number of cached inodes
    capacity: usize,
    /// Cache statistics
    stats: Mutex<CacheStats>,
    /// Clock for entry aging
    clock: MonotonicClock,
}

unsafe impl Send for InodeCache {}
unsafe impl Sync for InodeCache {}

impl InodeCache {
    /// Create a new inode cache
    pub fn new(
        device: Arc<dyn BlockIO>,
        superblock: Arc<Superblock>,
        bgdt: Arc<[BlockGroupDescriptor]>,
        block_cache: Arc<dyn Cache<u32, super::block::CachedBlock>>,
        capacity: usize,
    ) -> Self {
        Self {
            device,
            superblock,
            bgdt,
            block_cache,
            entries: Mutex::new(BTreeMap::new()),
            capacity,
            stats: Mutex::default(),
            clock: MonotonicClock::default(),
        }
    }

    /// Calculate the location of an inode
    fn get_inode_location(&self, inode_no: u32) -> InodeLocation {
        let inodes_per_group = self.superblock.inodes_per_group;
        let block_size = self.superblock.block_size();
        let inode_size = 128; // Standard ext2 inode size

        let block_group = (inode_no - 1) / inodes_per_group;
        let index = (inode_no - 1) % inodes_per_group;
        let block_offset = (index * inode_size) / block_size;
        let offset = (index * inode_size) % block_size;

        let inode_table = self.bgdt[block_group as usize].inode_table_block;
        let block = inode_table + block_offset;

        InodeLocation {
            block_group,
            index,
            block,
            offset,
        }
    }

    /// Find the least recently used entry that can be evicted
    fn find_lru_entry(&self, entries: &BTreeMap<u32, CacheEntry<CachedInode>>) -> Option<u32> {
        entries
            .iter()
            .filter(|(_, entry)| entry.value.lock().ref_count() == 0)
            .min_by_key(|(_, entry)| (entry.last_access, entry.access_count))
            .map(|(inode_no, _)| *inode_no)
    }

    /// Load an inode from the device
    fn load_inode(&self, inode_no: u32) -> CacheResult<CachedInode> {
        let location = self.get_inode_location(inode_no);

        // Get the block containing this inode
        let block = self.block_cache.get(location.block)?;

        // Read the inode from the block
        let inode = unsafe {
            let guard = block.lock();
            let data = guard.data();
            let ptr = data.as_ptr().add(location.offset as usize) as *const Inode;
            (*ptr).clone() // Clone the data while the guard is still alive
        };

        Ok(CachedInode::new(inode, inode_no))
    }

    /// Write an inode back to the device
    fn write_inode(&self, inode_no: u32, cached: &CachedInode) -> CacheResult<()> {
        if !cached.is_dirty() {
            return Ok(());
        }

        let location = self.get_inode_location(inode_no);

        // Get the block containing this inode
        let block = self.block_cache.get(location.block)?;

        // Write the inode to the block
        unsafe {
            let mut guard = block.lock();
            let data = guard.data_mut();
            let ptr = data.as_mut_ptr().add(location.offset as usize) as *mut Inode;
            *ptr = cached.inode.clone();
        }

        Ok(())
    }

    /// Evict entries if cache is full
    fn evict_if_needed(
        &self,
        entries: &mut BTreeMap<u32, CacheEntry<CachedInode>>,
    ) -> CacheResult<()> {
        if entries.len() < self.capacity {
            return Ok(());
        }

        if let Some(inode_no) = self.find_lru_entry(entries) {
            let entry = entries.remove(&inode_no).unwrap();

            // Write back if dirty
            if entry.value.lock().is_dirty() {
                self.write_inode(inode_no, &entry.value.lock())?;
                self.stats.lock().writebacks += 1;
            }

            self.stats.lock().evictions += 1;
            Ok(())
        } else {
            Err(CacheError::CacheFull)
        }
    }
}

impl Cache<u32, CachedInode> for InodeCache {
    fn get(&self, inode_no: u32) -> CacheResult<Arc<Mutex<CachedInode>>> {
        let mut entries = self.entries.lock();
        let now = self.clock.now();

        // Check if inode is cached
        if let Some(entry) = entries.get_mut(&inode_no) {
            entry.touch(now);
            self.stats.lock().hits += 1;
            entry.value.lock().inc_ref();
            return Ok(Arc::clone(&entry.value));
        }

        // Need to load inode
        self.stats.lock().misses += 1;

        // Evict if needed
        self.evict_if_needed(&mut entries)?;

        // Load and cache inode
        let cached = self.load_inode(inode_no)?;
        let entry = CacheEntry::new(cached);
        let value = Arc::clone(&entry.value);
        entries.insert(inode_no, entry);

        Ok(value)
    }

    fn insert(&self, inode_no: u32, cached: CachedInode) -> CacheResult<()> {
        let mut entries = self.entries.lock();

        // Evict if needed
        self.evict_if_needed(&mut entries)?;

        // Add new entry
        entries.insert(inode_no, CacheEntry::new(cached));
        Ok(())
    }

    fn remove(&self, inode_no: &u32) -> CacheResult<()> {
        let mut entries = self.entries.lock();

        if let Some(entry) = entries.remove(inode_no) {
            // We can clone the Arc to check ref count without holding the full entry
            let value = Arc::clone(&entry.value);
            let cached = value.lock();

            if cached.ref_count() > 0 {
                // Still referenced, put it back
                entries.insert(*inode_no, entry);
            } else if cached.is_dirty() {
                // No references but dirty, write back
                self.write_inode(*inode_no, &cached)?;
                self.stats.lock().writebacks += 1;
            }
        }

        Ok(())
    }

    fn clear(&self) -> CacheResult<()> {
        let mut entries = self.entries.lock();

        // Write back all dirty blocks
        for (inode_no, entry) in entries.iter() {
            let cached = entry.value.lock();
            if cached.ref_count() == 0 && cached.is_dirty() {
                self.write_inode(*inode_no, &cached)?;
                self.stats.lock().writebacks += 1;
            }
        }

        // Only remove unreferenced entries
        entries.retain(|_, entry| entry.value.lock().ref_count() > 0);
        Ok(())
    }

    fn stats(&self) -> CacheStats {
        self.stats.lock().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            super::block_io::MockDevice,
            block::{BlockCache, CachedBlock},
        },
        *,
    };
    use alloc::{sync::Arc, vec};

    // Test CachedInode functionality
    #[test_case]
    fn test_cached_inode_basic() {
        let inode = Inode {
            mode: 0,
            uid: 0,
            size_low: 1024,
            links_count: 1,
            blocks: [0; 15],
            ..Default::default()
        };

        let mut cached = CachedInode::new(inode, 1);
        assert_eq!(cached.ref_count(), 1);
        assert!(!cached.is_dirty());

        // Modify inode
        {
            let inode = cached.inode_mut();
            inode.size_low = 2048;
        }
        assert!(cached.is_dirty());
    }

    #[test_case]
    fn test_cached_inode_ref_counting() {
        let inode = Inode {
            links_count: 1,
            blocks: [0; 15],
            ..Default::default()
        };
        let cached = CachedInode::new(inode, 1);

        assert_eq!(cached.ref_count(), 1);
        cached.inc_ref();
        assert_eq!(cached.ref_count(), 2);
        assert_eq!(cached.dec_ref(), 2);
        assert_eq!(cached.ref_count(), 1);
    }

    // Helper function to set up test environment
    fn setup_test_cache(
        capacity: usize,
    ) -> (
        Arc<dyn BlockIO>,
        Arc<Superblock>,
        Arc<[BlockGroupDescriptor]>,
        Arc<dyn Cache<u32, CachedBlock>>,
        InodeCache,
    ) {
        let device: Arc<dyn BlockIO> = MockDevice::new(1024, 1024 * 1024);

        let superblock = Arc::new(Superblock {
            block_size_shift: 10, // 1024 bytes
            inodes_per_group: 8,
            ..Default::default()
        });

        let bgdt: Arc<[BlockGroupDescriptor]> =
            Arc::from(vec![BlockGroupDescriptor::new(0, 0, 1, 0, 0, 0)]);

        let block_cache =
            Arc::new(BlockCache::new(device.clone(), 8)) as Arc<dyn Cache<u32, CachedBlock>>;

        let cache = InodeCache::new(
            device.clone(),
            superblock.clone(),
            bgdt.clone(),
            block_cache.clone(),
            capacity,
        );

        (device, superblock, bgdt, block_cache, cache)
    }

    // Test InodeCache functionality
    #[test_case]
    fn test_inode_cache_basic() {
        let (_device, _superblock, _bgdt, _block_cache, cache) = setup_test_cache(4);

        // Get an inode
        let inode = cache.get(1).unwrap();
        assert_eq!(inode.lock().ref_count(), 1);
    }

    #[test_case]
    fn test_inode_cache_eviction() {
        let (_device, _superblock, _bgdt, _block_cache, cache) = setup_test_cache(2);

        // Fill cache
        {
            let inode1 = cache.get(1).unwrap();
            inode1.lock().dec_ref();
        }
        {
            let inode2 = cache.get(2).unwrap();
            inode2.lock().dec_ref();
        }

        // This should trigger eviction
        let _inode3 = cache.get(3).unwrap();

        let stats = cache.stats();
        assert!(stats.evictions > 0);
    }

    #[test_case]
    fn test_inode_cache_dirty_writeback() {
        let (_device, _superblock, _bgdt, _block_cache, cache) = setup_test_cache(4);

        // Modify an inode
        {
            let inode = cache.get(1).unwrap();
            let mut guard = inode.lock();
            guard.inode_mut().size_low = 1024;
            guard.dec_ref();
        }

        // Clear cache should trigger writeback
        cache.clear().unwrap();

        let stats = cache.stats();
        assert!(stats.writebacks > 0);
    }

    #[test_case]
    fn test_inode_location_calculation() {
        let device: Arc<dyn BlockIO> = MockDevice::new(1024, 1024 * 1024);

        let superblock = Arc::new(Superblock {
            block_size_shift: 10,
            inodes_per_group: 8,
            ..Default::default()
        });

        let bgdt: Arc<[BlockGroupDescriptor]> = Arc::from(vec![
            BlockGroupDescriptor::new(0, 0, 10, 0, 0, 0),
            BlockGroupDescriptor::new(0, 0, 20, 0, 0, 0),
        ]);

        let block_cache =
            Arc::new(BlockCache::new(device.clone(), 8)) as Arc<dyn Cache<u32, CachedBlock>>;

        let cache = InodeCache::new(device, superblock, bgdt, block_cache, 4);

        // Test inode location calculation
        let location = cache.get_inode_location(9); // Second group, first inode
        assert_eq!(location.block_group, 1); // Should be in second group
        assert_eq!(location.index, 0); // First inode in group
        assert_eq!(location.block, 20);
    }

    #[test_case]
    fn test_inode_cache_reference_handling() {
        let (_device, _superblock, _bgdt, _block_cache, cache) = setup_test_cache(2);

        // Get multiple references to same inode
        {
            let inode1 = cache.get(1).unwrap();
            {
                let inode2 = cache.get(1).unwrap();
                {
                    let guard = inode1.lock();
                    assert_eq!(guard.ref_count(), 2);
                    guard.dec_ref();
                }

                // Drop one reference
                drop(inode1);

                {
                    let guard = inode2.lock();
                    assert_eq!(guard.ref_count(), 1);
                    guard.dec_ref();
                }

                // Try to evict - should not work while referenced
                let inode3 = cache.get(2).unwrap();
                {
                    let guard = inode3.lock();
                    guard.dec_ref();
                }
                let inode4 = cache.get(3).unwrap(); // Should not evict inode 1
                {
                    let guard = inode4.lock();
                    guard.dec_ref();
                }

                assert!(cache.get(1).is_ok()); // Should still be in cache
            }
        }
    }
}
