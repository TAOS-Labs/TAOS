// We want to make this replace the block IO we have right now
// But would it matter if this is not in kernel anyways?

use alloc::vec::Vec;
use core::cmp::min;

/// Represents errors that can occur during block I/O operations
#[derive(Debug)]
pub enum BlockError {
    /// The requested offset is beyond the end of the device/file
    OffsetOutOfBounds,
    /// Device reported an error during operation
    DeviceError,
    /// Invalid block number requested
    InvalidBlock,
    /// End of file/device reached
    EndOfDevice,
}

pub type BlockResult<T> = Result<T, BlockError>;

/// Trait for devices or files that can be accessed in blocks
pub trait BlockIO: Send + Sync {
    /// Returns the block size in bytes
    fn block_size(&self) -> u32;

    /// Returns the total size in bytes
    fn size_in_bytes(&self) -> u32;

    /// Returns the number of blocks
    fn size_in_blocks(&self) -> u32 {
        (self.size_in_bytes() + self.block_size() - 1) / self.block_size()
    }

    /// Read a block into the provided buffer
    ///
    /// # Arguments
    /// * `block_number` - The block number to read
    /// * `buffer` - Buffer to read into, must be at least block_size() bytes
    fn read_block(&self, block_number: u32, buffer: &mut [u8]) -> BlockResult<()>;

    /// Read bytes from a specific offset
    ///
    /// # Arguments
    /// * `offset` - Byte offset to start reading from
    /// * `buffer` - Buffer to read into
    ///
    /// # Returns
    /// * Number of bytes read if successful
    /// * Error if offset is invalid or device error occurs
    fn read(&self, offset: u32, buffer: &mut [u8]) -> BlockResult<u32> {
        let sz = self.size_in_bytes();
        if offset >= sz {
            return if offset == sz {
                Ok(0)
            } else {
                Err(BlockError::OffsetOutOfBounds)
            };
        }

        let n = min(buffer.len() as u32, sz - offset);
        let block_number = offset / self.block_size();
        let offset_in_block = offset % self.block_size();
        let actual_n = min(self.block_size() - offset_in_block, n);

        if actual_n == self.block_size() && offset_in_block == 0 {
            self.read_block(block_number, &mut buffer[..actual_n as usize])?;
        } else {
            let mut temp = Vec::with_capacity(self.block_size() as usize);
            unsafe {
                temp.set_len(self.block_size() as usize);
                self.read_block(block_number, &mut temp)?;
                buffer[..actual_n as usize].copy_from_slice(
                    &temp[offset_in_block as usize..(offset_in_block + actual_n) as usize],
                );
            }
        }

        Ok(actual_n)
    }

    /// Read exactly n bytes from offset or until EOF
    fn read_exact(&self, mut offset: u32, buffer: &mut [u8]) -> BlockResult<u32> {
        let mut total_count = 0;
        let mut remaining = buffer.len();
        let mut buf_offset = 0;

        while remaining > 0 {
            match self.read(offset, &mut buffer[buf_offset..]) {
                Ok(0) => return Ok(total_count),
                Ok(n) => {
                    total_count += n;
                    offset += n;
                    buf_offset += n as usize;
                    remaining -= n as usize;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(total_count)
    }

    /// Write a block
    fn write_block(&self, block_number: u32, buffer: &[u8]) -> BlockResult<()>;

    /// Write bytes at a specific offset
    fn write(&self, offset: u32, buffer: &[u8]) -> BlockResult<u32> {
        let sz = self.size_in_bytes();
        if offset >= sz {
            return Err(BlockError::OffsetOutOfBounds);
        }

        let n = min(buffer.len() as u32, sz - offset);
        let block_number = offset / self.block_size();
        let offset_in_block = offset % self.block_size();
        let actual_n = min(self.block_size() - offset_in_block, n);

        if actual_n == self.block_size() && offset_in_block == 0 {
            self.write_block(block_number, &buffer[..actual_n as usize])?;
        } else {
            let mut temp = Vec::with_capacity(self.block_size() as usize);
            unsafe {
                temp.set_len(self.block_size() as usize);
                // Read-modify-write
                self.read_block(block_number, &mut temp)?;
                temp[offset_in_block as usize..(offset_in_block + actual_n) as usize]
                    .copy_from_slice(&buffer[..actual_n as usize]);
                self.write_block(block_number, &temp)?;
            }
        }

        Ok(actual_n)
    }
}
