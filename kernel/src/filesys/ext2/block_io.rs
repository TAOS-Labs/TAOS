// We want to make this replace the block IO we have right now
// But would it matter if this is not in kernel anyways?

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::cmp::min;
use spin::Mutex;

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

// Mock block device for testing
pub struct MockDevice {
    block_size: u32,
    size: u32,
    blocks: Mutex<BTreeMap<u32, Vec<u8>>>,
}

impl MockDevice {
    pub fn new(block_size: u32, size: u32) -> Arc<Self> {
        Arc::new(Self {
            block_size,
            size,
            blocks: Mutex::new(BTreeMap::new()),
        })
    }
}

impl BlockIO for MockDevice {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn size_in_bytes(&self) -> u32 {
        self.size
    }

    fn size_in_blocks(&self) -> u32 {
        (self.size + self.block_size - 1) / self.block_size
    }

    fn read_block(&self, block_number: u32, buffer: &mut [u8]) -> BlockResult<()> {
        if buffer.len() < self.block_size as usize {
            return Err(BlockError::InvalidBlock);
        }

        let blocks = self.blocks.lock();
        if let Some(data) = blocks.get(&block_number) {
            buffer[..data.len()].copy_from_slice(data);
            Ok(())
        } else {
            // Unwritten blocks return zeros
            buffer[..self.block_size as usize].fill(0);
            Ok(())
        }
    }

    fn write_block(&self, block_number: u32, buffer: &[u8]) -> BlockResult<()> {
        if buffer.len() < self.block_size as usize {
            return Err(BlockError::InvalidBlock);
        }

        if block_number >= self.size_in_blocks() {
            return Err(BlockError::InvalidBlock);
        }

        let mut blocks = self.blocks.lock();
        blocks.insert(block_number, buffer[..self.block_size as usize].to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
    use spin::Mutex;

    // Test basic block operations
    #[test_case]
    fn test_basic_block_operations() {
        let device = MockDevice::new(1024, 1024 * 1024); // 1MB device with 1KB blocks

        // Write a block
        let data = vec![0x55; 1024];
        device.write_block(0, &data).unwrap();

        // Read it back
        let mut buffer = vec![0; 1024];
        device.read_block(0, &mut buffer).unwrap();
        assert_eq!(buffer, data);

        // Read an unwritten block (should be zeros)
        let mut buffer = vec![0; 1024];
        device.read_block(1, &mut buffer).unwrap();
        assert!(buffer.iter().all(|&x| x == 0));
    }

    // Test partial reads
    #[test_case]
    fn test_partial_reads() {
        let device = MockDevice::new(1024, 1024 * 1024); // 1MB device with 1KB blocks

        // Write some data
        let data = vec![0x55; 1024];
        device.write_block(0, &data).unwrap();

        // Test reading first half of block
        let mut buffer = vec![0; 512];
        assert_eq!(device.read(0, &mut buffer).unwrap(), 512);
        assert_eq!(&buffer[..], &data[..512]);

        // Test reading second half of block
        let mut buffer = vec![0; 512];
        assert_eq!(device.read(512, &mut buffer).unwrap(), 512);
        assert_eq!(&buffer[..], &data[512..]);

        // Test reading with offset that would cross block boundary
        // Should only read to end of current block
        let mut buffer = vec![0xff; 1536]; // Fill with 0xff to verify untouched regions
        assert_eq!(device.read(512, &mut buffer).unwrap(), 512);
        assert_eq!(&buffer[..512], &data[512..]);
        assert!(buffer[512..].iter().all(|&x| x == 0xff)); // Verify rest was untouched
    }

    // Test invalid operations
    #[test_case]
    fn test_invalid_operations() {
        let device = MockDevice::new(1024, 1024 * 1024);

        // Try to write with too small buffer
        let data = vec![0; 512];
        assert!(matches!(
            device.write_block(0, &data),
            Err(BlockError::InvalidBlock)
        ));

        // Try to read with too small buffer
        let mut buffer = vec![0; 512];
        assert!(matches!(
            device.read_block(0, &mut buffer),
            Err(BlockError::InvalidBlock)
        ));

        // Try to access beyond device size
        let data = vec![0; 1024];
        assert!(matches!(
            device.write_block(2048, &data),
            Err(BlockError::InvalidBlock)
        ));
    }

    // Test block boundaries
    #[test_case]
    fn test_block_boundaries() {
        let device = MockDevice::new(1024, 2048); // 2 blocks exactly

        // Write last block
        let data = vec![0x55; 1024];
        device.write_block(1, &data).unwrap();

        // Verify size calculations
        assert_eq!(device.size_in_blocks(), 2);
        assert_eq!(device.size_in_bytes(), 2048);

        // Try to write beyond last block
        assert!(matches!(
            device.write_block(2, &data),
            Err(BlockError::InvalidBlock)
        ));
    }

    // Test read_exact
    #[test_case]
    fn test_read_exact() {
        let device = MockDevice::new(1024, 4096); // 4 blocks

        // Write some data
        let data = vec![0x55; 1024];
        device.write_block(0, &data).unwrap();
        device.write_block(1, &data).unwrap();

        // Read exact amount
        let mut buffer = vec![0; 2048];
        assert_eq!(device.read_exact(0, &mut buffer).unwrap(), 2048);

        // Try to read beyond device size
        let mut buffer = vec![0; 8192];
        assert_eq!(device.read_exact(0, &mut buffer).unwrap(), 4096); // Should read until end
    }
}
