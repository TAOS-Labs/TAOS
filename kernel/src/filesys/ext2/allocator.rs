use alloc::{sync::Arc, vec::Vec};
use spin::Mutex;

use super::{
    cache::{block::CachedBlock, Cache},
    structures::{BlockGroupDescriptor, Superblock},
};

/// Errors that can occur during allocation
#[derive(Debug)]
pub enum AllocError {
    /// No free blocks/inodes available
    NoSpace,
    /// Cache error
    CacheError,
    /// Invalid block/inode number
    InvalidNumber,
    /// Bitmap read/write error
    BitmapError,
}

pub type AllocResult<T> = Result<T, AllocError>;

/// Manages block and inode allocation
pub struct Allocator {
    superblock: Arc<Superblock>,
    bgdt: Arc<[BlockGroupDescriptor]>,
    block_cache: Arc<dyn Cache<u32, CachedBlock>>,
    /// Locks for each block group to prevent concurrent allocation
    group_locks: Vec<Mutex<()>>,
}

unsafe impl Send for Allocator {}
unsafe impl Sync for Allocator {}

impl Allocator {
    /// Create a new allocator
    pub fn new(
        superblock: Arc<Superblock>,
        bgdt: Arc<[BlockGroupDescriptor]>,
        block_cache: Arc<dyn Cache<u32, CachedBlock>>,
    ) -> Self {
        let num_groups = superblock.block_group_count() as usize;
        let group_locks = (0..num_groups).map(|_| Mutex::new(())).collect();

        Self {
            superblock,
            bgdt,
            block_cache,
            group_locks,
        }
    }

    /// Find the first zero bit in a bitmap
    fn find_first_zero(bitmap: &[u8]) -> Option<usize> {
        for (byte_idx, &byte) in bitmap.iter().enumerate() {
            if byte != 0xff {
                let bit_idx = byte.trailing_ones() as usize;
                return Some(byte_idx * 8 + bit_idx);
            }
        }
        None
    }

    /// Set a bit in a bitmap
    fn set_bit(bitmap: &mut [u8], bit: usize) {
        let byte = bit / 8;
        let bit = bit % 8;
        bitmap[byte] |= 1 << bit;
    }

    /// Clear a bit in a bitmap
    fn clear_bit(bitmap: &mut [u8], bit: usize) {
        let byte = bit / 8;
        let bit = bit % 8;
        bitmap[byte] &= !(1 << bit);
    }

    /// Test if a bit is set in a bitmap
    #[allow(dead_code)]
    fn test_bit(bitmap: &[u8], bit: usize) -> bool {
        let byte = bit / 8;
        let bit = bit % 8;
        bitmap[byte] & (1 << bit) != 0
    }

    /// Allocate a block in a specific group
    fn allocate_block_in_group(&self, group: usize) -> AllocResult<u32> {
        let bgdt = self.bgdt.get(group).ok_or(AllocError::InvalidNumber)?;
        let _guard = self
            .group_locks
            .get(group)
            .ok_or(AllocError::InvalidNumber)?
            .lock();

        // Read the bitmap
        let bitmap_block = self
            .block_cache
            .get(bgdt.block_bitmap_block)
            .map_err(|_| AllocError::CacheError)?;
        let mut bitmap_block = bitmap_block.lock();
        let bitmap = bitmap_block.data_mut();

        // Find a free block
        let bit = Self::find_first_zero(bitmap).ok_or(AllocError::NoSpace)?;

        // Check if bit is within bounds
        if bit >= self.superblock.blocks_per_group as usize {
            return Err(AllocError::NoSpace);
        }

        // Mark block as used
        Self::set_bit(bitmap, bit);

        // Calculate global block number
        let block = group as u32 * self.superblock.blocks_per_group + bit as u32;
        if block >= self.superblock.num_blocks {
            return Err(AllocError::NoSpace);
        }

        Ok(block)
    }

    /// Allocate an inode in a specific group
    fn allocate_inode_in_group(&self, group: usize) -> AllocResult<u32> {
        let bgdt = self.bgdt.get(group).ok_or(AllocError::InvalidNumber)?;
        let _guard = self
            .group_locks
            .get(group)
            .ok_or(AllocError::InvalidNumber)?
            .lock();

        // Read the bitmap
        let bitmap_block = self
            .block_cache
            .get(bgdt.inode_bitmap_block)
            .map_err(|_| AllocError::CacheError)?;
        let mut bitmap_block = bitmap_block.lock();
        let bitmap = bitmap_block.data_mut();

        // Find a free inode
        let bit = Self::find_first_zero(bitmap).ok_or(AllocError::NoSpace)?;

        // Check if bit is within bounds
        if bit >= self.superblock.inodes_per_group as usize {
            return Err(AllocError::NoSpace);
        }

        // Mark inode as used
        Self::set_bit(bitmap, bit);

        // Calculate global inode number (1-based)
        let inode = group as u32 * self.superblock.inodes_per_group + bit as u32 + 1;
        if inode > self.superblock.num_inodes {
            return Err(AllocError::NoSpace);
        }

        Ok(inode)
    }

    /// Allocate a new block
    pub fn allocate_block(&self) -> AllocResult<u32> {
        let num_groups = self.superblock.block_group_count() as usize;

        // Try to allocate from each group
        for group in 0..num_groups {
            if let Some(desc) = self.bgdt.get(group) {
                if desc.unallocated_blocks > 0 {
                    if let Ok(block) = self.allocate_block_in_group(group) {
                        // Update free blocks count
                        unsafe {
                            let bgdt = desc as *const _ as *mut BlockGroupDescriptor;
                            (*bgdt).unallocated_blocks -= 1;
                        }
                        return Ok(block);
                    }
                }
            }
        }

        Err(AllocError::NoSpace)
    }

    /// Allocate a new inode
    pub fn allocate_inode(&self) -> AllocResult<u32> {
        let num_groups = self.superblock.block_group_count() as usize;

        // Try to allocate from each group
        for group in 0..num_groups {
            if let Some(desc) = self.bgdt.get(group) {
                if desc.unallocated_inodes > 0 {
                    if let Ok(inode) = self.allocate_inode_in_group(group) {
                        // Update free inodes count
                        unsafe {
                            let bgdt = desc as *const _ as *mut BlockGroupDescriptor;
                            (*bgdt).unallocated_inodes -= 1;
                        }
                        return Ok(inode);
                    }
                }
            }
        }

        Err(AllocError::NoSpace)
    }

    /// Free a block
    pub fn free_block(&self, block: u32) -> AllocResult<()> {
        let blocks_per_group = self.superblock.blocks_per_group;

        let group = (block / blocks_per_group) as usize;
        let index = (block % blocks_per_group) as usize;

        let bgdt = self.bgdt.get(group).ok_or(AllocError::InvalidNumber)?;
        let _guard = self
            .group_locks
            .get(group)
            .ok_or(AllocError::InvalidNumber)?
            .lock();

        // Read the bitmap
        let bitmap_block = self
            .block_cache
            .get(bgdt.block_bitmap_block)
            .map_err(|_| AllocError::CacheError)?;
        let mut bitmap_block = bitmap_block.lock();
        let bitmap = bitmap_block.data_mut();

        // Clear the bit
        Self::clear_bit(bitmap, index);

        // Update free blocks count
        unsafe {
            let bgdt = bgdt as *const _ as *mut BlockGroupDescriptor;
            (*bgdt).unallocated_blocks += 1;
        }

        Ok(())
    }

    /// Free an inode
    pub fn free_inode(&self, inode: u32) -> AllocResult<()> {
        let inodes_per_group = self.superblock.inodes_per_group;

        // Convert to 0-based index
        let inode = inode - 1;

        let group = (inode / inodes_per_group) as usize;
        let index = (inode % inodes_per_group) as usize;

        let bgdt = self.bgdt.get(group).ok_or(AllocError::InvalidNumber)?;
        let _guard = self
            .group_locks
            .get(group)
            .ok_or(AllocError::InvalidNumber)?
            .lock();

        // Read the bitmap
        let bitmap_block = self
            .block_cache
            .get(bgdt.inode_bitmap_block)
            .map_err(|_| AllocError::CacheError)?;
        let mut bitmap_block = bitmap_block.lock();
        let bitmap = bitmap_block.data_mut();

        // Clear the bit
        Self::clear_bit(bitmap, index);

        // Update free inodes count
        unsafe {
            let bgdt = bgdt as *const _ as *mut BlockGroupDescriptor;
            (*bgdt).unallocated_inodes += 1;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{block_io::MockDevice, cache::block::BlockCache},
        *,
    };
    use alloc::{sync::Arc, vec};

    #[test_case]
    fn test_bitmap_operations() {
        let mut bitmap = vec![0u8; 32]; // 256 bits

        // Test setting bits
        Allocator::set_bit(&mut bitmap, 0);
        assert!(Allocator::test_bit(&bitmap, 0));

        Allocator::set_bit(&mut bitmap, 7);
        assert!(Allocator::test_bit(&bitmap, 7));

        // Test clearing bits
        Allocator::clear_bit(&mut bitmap, 0);
        assert!(!Allocator::test_bit(&bitmap, 0));

        // Test finding first zero
        assert_eq!(Allocator::find_first_zero(&bitmap), Some(0));

        // Fill bitmap
        for i in 0..8 {
            Allocator::set_bit(&mut bitmap, i);
        }
        assert_eq!(Allocator::find_first_zero(&bitmap), Some(8));

        // Fill completely
        for i in 0..256 {
            Allocator::set_bit(&mut bitmap, i);
        }
        assert_eq!(Allocator::find_first_zero(&bitmap), None);
    }

    struct TestSetup {
        device: Arc<MockDevice>,
        superblock: Arc<Superblock>,
        bgdt: Arc<[BlockGroupDescriptor]>,
        block_cache: Arc<BlockCache>,
        allocator: Arc<Allocator>,
    }

    impl TestSetup {
        fn new() -> Self {
            let device = MockDevice::new(1024, 1024 * 1024); // 1MB device

            let superblock = Arc::new(Superblock {
                num_blocks: 1024,
                num_inodes: 256,
                blocks_per_group: 256,
                inodes_per_group: 64,
                block_size_shift: 10, // 1024 bytes
                ..Default::default()
            });

            // Create 4 block groups
            let mut bgdt = Vec::new();
            for i in 0..4 {
                bgdt.push(BlockGroupDescriptor {
                    block_bitmap_block: i * 256,
                    inode_bitmap_block: i * 256 + 1,
                    inode_table_block: i * 256 + 2,
                    unallocated_blocks: 253, // Account for bitmap and table blocks
                    unallocated_inodes: 64,
                    ..Default::default()
                });
            }

            let bgdt = Arc::new(bgdt);
            let block_cache = Arc::new(BlockCache::new(Arc::clone(&device), 16));

            let allocator = Arc::new(Allocator::new(
                Arc::clone(&superblock),
                Arc::clone(&bgdt),
                Arc::clone(&block_cache),
            ));

            Self {
                device,
                superblock,
                bgdt,
                block_cache,
                allocator,
            }
        }
    }

    #[test_case]
    fn test_block_allocation() {
        let setup = TestSetup::new();

        // Allocate first block
        let block1 = setup.allocator.allocate_block().unwrap();
        assert!(block1 > 0); // First few blocks are reserved

        // Verify block is marked in bitmap
        let bgdt = &setup.bgdt[0];
        let bitmap_block = setup.block_cache.get(bgdt.block_bitmap_block).unwrap();
        let bitmap = bitmap_block.lock();
        assert!(Allocator::test_bit(bitmap.data(), (block1 % 256) as usize));

        // Free count should decrease
        assert_eq!(bgdt.unallocated_blocks, 252);
    }

    #[test_case]
    fn test_inode_allocation() {
        let setup = TestSetup::new();

        // Allocate first inode
        let inode1 = setup.allocator.allocate_inode().unwrap();
        assert!(inode1 > 0);

        // Verify inode is marked in bitmap
        let bgdt = &setup.bgdt[0];
        let bitmap_block = setup.block_cache.get(bgdt.inode_bitmap_block).unwrap();
        let bitmap = bitmap_block.lock();
        assert!(Allocator::test_bit(
            bitmap.data(),
            ((inode1 - 1) % 64) as usize
        ));

        // Free count should decrease
        assert_eq!(bgdt.unallocated_inodes, 63);
    }

    #[test_case]
    fn test_block_deallocation() {
        let setup = TestSetup::new();

        // Allocate and free a block
        let block = setup.allocator.allocate_block().unwrap();
        setup.allocator.free_block(block).unwrap();

        // Verify block is unmarked in bitmap
        let bgdt = &setup.bgdt[0];
        let bitmap_block = setup.block_cache.get(bgdt.block_bitmap_block).unwrap();
        let bitmap = bitmap_block.lock();
        assert!(!Allocator::test_bit(bitmap.data(), (block % 256) as usize));

        // Free count should be restored
        assert_eq!(bgdt.unallocated_blocks, 253);
    }

    #[test_case]
    fn test_inode_deallocation() {
        let setup = TestSetup::new();

        // Allocate and free an inode
        let inode = setup.allocator.allocate_inode().unwrap();
        setup.allocator.free_inode(inode).unwrap();

        // Verify inode is unmarked in bitmap
        let bgdt = &setup.bgdt[0];
        let bitmap_block = setup.block_cache.get(bgdt.inode_bitmap_block).unwrap();
        let bitmap = bitmap_block.lock();
        assert!(!Allocator::test_bit(
            bitmap.data(),
            ((inode - 1) % 64) as usize
        ));

        // Free count should be restored
        assert_eq!(bgdt.unallocated_inodes, 64);
    }

    #[test_case]
    fn test_exhaustion() {
        let setup = TestSetup::new();

        // Allocate all blocks in first group
        let mut blocks = Vec::new();
        while let Ok(block) = setup.allocator.allocate_block() {
            blocks.push(block);
            if blocks.len() >= 253 {
                // All free blocks in first group
                break;
            }
        }

        // Next allocation should come from second group
        let next_block = setup.allocator.allocate_block().unwrap();
        assert!(next_block >= 256); // Should be in second group

        // Free all blocks
        for block in blocks {
            setup.allocator.free_block(block).unwrap();
        }
    }

    #[test_case]
    fn test_invalid_operations() {
        let setup = TestSetup::new();

        // Try to free invalid block
        assert!(matches!(
            setup.allocator.free_block(setup.superblock.num_blocks + 1),
            Err(AllocError::InvalidNumber)
        ));

        // Try to free invalid inode
        assert!(matches!(
            setup.allocator.free_inode(setup.superblock.num_inodes + 1),
            Err(AllocError::InvalidNumber)
        ));
    }
}
