use alloc::{boxed::Box, sync::Arc, vec::Vec};
use spin::{Mutex, RwLock};

use super::{
    cache::{block::CachedBlock, Cache, CacheableItem},
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
    superblock: Arc<RwLock<Superblock>>,
    bgdt: Arc<RwLock<Vec<BlockGroupDescriptor>>>,
    block_cache: Arc<Mutex<Box<dyn Cache<u32, CachedBlock>>>>,
    /// Locks for each block group to prevent concurrent allocation
    group_locks: Vec<Mutex<()>>,
}

impl Allocator {
    /// Create a new allocator
    pub fn new(
        superblock: Arc<RwLock<Superblock>>,
        bgdt: Arc<RwLock<Vec<BlockGroupDescriptor>>>,
        block_cache: Arc<Mutex<Box<dyn Cache<u32, CachedBlock>>>>,
    ) -> Self {
        let num_groups = {
            let superblock = superblock.read();
            superblock.block_group_count() as usize
        };
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
        let superblock = self.superblock.read();
        let bgdt_read = self.bgdt.read();

        let bgdt = bgdt_read.get(group).ok_or(AllocError::InvalidNumber)?;
        let _guard = self
            .group_locks
            .get(group)
            .ok_or(AllocError::InvalidNumber)?
            .lock();

        let block_cache = self.block_cache.lock();
        let bitmap_block = block_cache
            .get(bgdt.block_bitmap_block)
            .await
            .map_err(|_| AllocError::CacheError)?;

        let mut bitmap_block = bitmap_block.lock();
        let bitmap = bitmap_block.data_mut();

        let bit = Self::find_first_zero(bitmap).ok_or(AllocError::NoSpace)?;

        if bit >= superblock.blocks_per_group as usize {
            return Err(AllocError::NoSpace);
        }

        Self::set_bit(bitmap, bit);
        bitmap_block.mark_dirty();

        let block = group as u32 * superblock.blocks_per_group + bit as u32;
        if block >= superblock.num_blocks {
            return Err(AllocError::NoSpace);
        }

        drop(bitmap_block);
        drop(block_cache);
        drop(bgdt_read);

        {
            let mut bgdt_write = self.bgdt.write();
            if let Some(desc) = bgdt_write.get_mut(group) {
                desc.unallocated_blocks -= 1;
            }
        }

        Ok(block)
    }

    /// Allocate an inode in a specific group
    async fn allocate_inode_in_group(&self, group: usize) -> AllocResult<u32> {
        let superblock = self.superblock.read();
        let bgdt_read = self.bgdt.read();

        let bgdt = bgdt_read.get(group).ok_or(AllocError::InvalidNumber)?;
        let _guard = self
            .group_locks
            .get(group)
            .ok_or(AllocError::InvalidNumber)?
            .lock();

        let block_cache = self.block_cache.lock();
        let bitmap_block = block_cache
            .get(bgdt.inode_bitmap_block)
            .await
            .map_err(|_| AllocError::CacheError)?;

        let mut bitmap_block = bitmap_block.lock();
        let bitmap = bitmap_block.data_mut();

        let bit = Self::find_first_zero(bitmap).ok_or(AllocError::NoSpace)?;

        if bit >= superblock.inodes_per_group as usize {
            return Err(AllocError::NoSpace);
        }

        Self::set_bit(bitmap, bit);
        bitmap_block.mark_dirty();

        let inode = group as u32 * superblock.inodes_per_group + bit as u32 + 1;
        if inode > superblock.num_inodes {
            return Err(AllocError::NoSpace);
        }

        drop(bitmap_block);
        drop(block_cache);
        drop(bgdt_read);

        {
            let mut bgdt_write = self.bgdt.write();
            if let Some(desc) = bgdt_write.get_mut(group) {
                desc.unallocated_inodes -= 1;
            }
        }

        Ok(inode)
    }

    /// Allocate a new block
    pub async fn allocate_block(&self) -> AllocResult<u32> {
        let num_groups = {
            let superblock = self.superblock.read();
            superblock.block_group_count() as usize
        };

        let bgdt_read = self.bgdt.read();

        let mut candidate_group = None;
        for group in 0..num_groups {
            if let Some(desc) = bgdt_read.get(group) {
                if desc.unallocated_blocks > 0 {
                    candidate_group = Some(group);
                    break;
                }
            }
        }

        drop(bgdt_read);

        if let Some(group) = candidate_group {
            return self.allocate_block_in_group(group).await;
        }

        Err(AllocError::NoSpace)
    }

    /// Allocate a new inode
    pub async fn allocate_inode(&self) -> AllocResult<u32> {
        let num_groups = {
            let superblock = self.superblock.read();
            superblock.block_group_count() as usize
        };

        let bgdt_read = self.bgdt.read();

        let mut candidate_group = None;
        for group in 0..num_groups {
            if let Some(desc) = bgdt_read.get(group) {
                if desc.unallocated_inodes > 0 {
                    candidate_group = Some(group);
                    break;
                }
            }
        }

        drop(bgdt_read);

        if let Some(group) = candidate_group {
            return self.allocate_inode_in_group(group).await;
        }

        Err(AllocError::NoSpace)
    }

    /// Free a block
    pub async fn free_block(&self, block: u32) -> AllocResult<()> {
        let (_, group, index) = {
            let superblock = self.superblock.read();
            let blocks_per_group = superblock.blocks_per_group;
            let group = (block / blocks_per_group) as usize;
            let index = (block % blocks_per_group) as usize;
            (blocks_per_group, group, index)
        };

        let bgdt_read = self.bgdt.read();
        let bgdt = bgdt_read.get(group).ok_or(AllocError::InvalidNumber)?;
        let _guard = self
            .group_locks
            .get(group)
            .ok_or(AllocError::InvalidNumber)?
            .lock();

        let block_cache = self.block_cache.lock();
        let bitmap_block = block_cache
            .get(bgdt.block_bitmap_block)
            .await
            .map_err(|_| AllocError::CacheError)?;

        let mut bitmap_block = bitmap_block.lock();
        let bitmap = bitmap_block.data_mut();

        Self::clear_bit(bitmap, index);
        bitmap_block.mark_dirty();

        drop(bitmap_block);
        drop(block_cache);
        drop(bgdt_read);

        {
            let mut bgdt_write = self.bgdt.write();
            if let Some(desc) = bgdt_write.get_mut(group) {
                desc.unallocated_blocks += 1;
            }
        }

        Ok(())
    }

    /// Free an inode
    pub async fn free_inode(&self, inode: u32) -> AllocResult<()> {
        let (_, group, index) = {
            let superblock = self.superblock.read();
            let inodes_per_group = superblock.inodes_per_group;

            let inode = inode - 1;

            let group = (inode / inodes_per_group) as usize;
            let index = (inode % inodes_per_group) as usize;
            (inodes_per_group, group, index)
        };

        let bgdt_read = self.bgdt.read();
        let bgdt = bgdt_read.get(group).ok_or(AllocError::InvalidNumber)?;
        let _guard = self
            .group_locks
            .get(group)
            .ok_or(AllocError::InvalidNumber)?
            .lock();

        let block_cache = self.block_cache.lock();
        let bitmap_block = block_cache
            .get(bgdt.inode_bitmap_block)
            .await
            .map_err(|_| AllocError::CacheError)?;

        let mut bitmap_block = bitmap_block.lock();
        let bitmap = bitmap_block.data_mut();

        Self::clear_bit(bitmap, index);
        bitmap_block.mark_dirty();

        drop(bitmap_block);
        drop(block_cache);
        drop(bgdt_read);

        {
            let mut bgdt_write = self.bgdt.write();
            if let Some(desc) = bgdt_write.get_mut(group) {
                desc.unallocated_inodes += 1;
            }
        }

        Ok(())
    }
}
