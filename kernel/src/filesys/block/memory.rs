//! In-memory block device implementation

use crate::filesys::{BlockDevice, FsError};
use alloc::{vec, vec::Vec, boxed::Box};
use async_trait::async_trait;
use core::result::Result;

/// Block device that stores data in memory
pub struct MemoryBlockDevice {
    /// Blocks of data, each block_size bytes
    blocks: Vec<Vec<u8>>,

    /// Size of each block in bytes
    block_size: usize,
}

impl MemoryBlockDevice {
    /// Creates a new memory block device with given size
    pub fn new(total_blocks: u64, block_size: usize) -> Self {
        let blocks = (0..total_blocks).map(|_| vec![0; block_size]).collect();
        Self { blocks, block_size }
    }

    /// Validates block number is within bounds
    fn validate_block(&self, block_num: u64) -> Result<(), FsError> {
        if block_num as usize >= self.blocks.len() {
            return Err(FsError::IOError);
        }
        Ok(())
    }

    /// Validates buffer is correct block size
    fn validate_buffer(&self, buf: &[u8]) -> Result<(), FsError> {
        if buf.len() != self.block_size {
            return Err(FsError::IOError);
        }
        Ok(())
    }
}

#[async_trait]
impl BlockDevice for MemoryBlockDevice {
    /// Reads block into buffer
    async fn read_block(&self, block_num: u64, buf: &mut [u8]) -> Result<(), FsError> {
        self.validate_block(block_num)?;
        self.validate_buffer(buf)?;
        buf.copy_from_slice(&self.blocks[block_num as usize]);
        Ok(())
    }

    /// Writes buffer to block
    async fn write_block(&mut self, block_num: u64, buf: &[u8]) -> Result<(), FsError> {
        self.validate_block(block_num)?;
        self.validate_buffer(buf)?;
        self.blocks[block_num as usize].copy_from_slice(buf);
        Ok(())
    }

    /// Returns size of each block
    fn block_size(&self) -> usize {
        self.block_size
    }

    /// Returns total number of blocks
    fn total_blocks(&self) -> u64 {
        self.blocks.len() as u64
    }
}
