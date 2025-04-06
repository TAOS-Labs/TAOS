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
    async fn allocate_block_in_group(&self, group: usize) -> AllocResult<u32> {
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
            .await
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
    async fn allocate_inode_in_group(&self, group: usize) -> AllocResult<u32> {
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
            .await
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
    pub async fn allocate_block(&self) -> AllocResult<u32> {
        let num_groups = self.superblock.block_group_count() as usize;

        // Try to allocate from each group
        for group in 0..num_groups {
            if let Some(desc) = self.bgdt.get(group) {
                if desc.unallocated_blocks > 0 {
                    if let Ok(block) = self.allocate_block_in_group(group).await {
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
    pub async fn allocate_inode(&self) -> AllocResult<u32> {
        let num_groups = self.superblock.block_group_count() as usize;

        // Try to allocate from each group
        for group in 0..num_groups {
            if let Some(desc) = self.bgdt.get(group) {
                if desc.unallocated_inodes > 0 {
                    if let Ok(inode) = self.allocate_inode_in_group(group).await {
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
    pub async fn free_block(&self, block: u32) -> AllocResult<()> {
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
            .await
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
    pub async fn free_inode(&self, inode: u32) -> AllocResult<()> {
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
            .await
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
