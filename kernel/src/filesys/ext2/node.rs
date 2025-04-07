use alloc::{string::String, sync::Arc, vec, vec::Vec};
use core::cmp::min;
use spin::Mutex;

use crate::serial_println;

use super::{
    allocator::{AllocError, Allocator},
    block_io::BlockError,
    cache::{block::CachedBlock, inode::CachedInode, Cache},
    get_current_time,
    structures::{DirectoryEntry, FileType},
};

/// Error types specific to node operations
#[derive(Debug)]
pub enum NodeError {
    NotDirectory,
    NotFile,
    NotSymlink,
    InvalidOffset,
    IoError(BlockError),
    CacheError,
    NameTooLong,
    NoSpace,
    WriteError,
    DirEntryTooLarge,
    NotEmpty,
    AlreadyExists,
    ReadOnly,
    NotFound,
}

impl From<AllocError> for NodeError {
    fn from(err: AllocError) -> Self {
        match err {
            AllocError::NoSpace => NodeError::NoSpace,
            _ => NodeError::WriteError,
        }
    }
}

pub type NodeResult<T> = Result<T, NodeError>;

/// Write context for managing block allocation
struct WriteContext<'a> {
    node: &'a Node,
    allocator: &'a Allocator,
    offset: u64,
    size: u64,
}

impl<'a> WriteContext<'a> {
    fn new(node: &'a Node, allocator: &'a Allocator, offset: u64, size: u64) -> Self {
        Self {
            node,
            allocator,
            offset,
            size,
        }
    }

    /// Ensure all necessary blocks are allocated
    async fn prepare_blocks(&mut self) -> NodeResult<()> {
        let start_block = self.offset / self.node.block_size as u64;
        let end_block = (self.offset + self.size).div_ceil(self.node.block_size as u64);

        for block_idx in start_block..end_block {
            self.ensure_block_allocated(block_idx).await?;
        }

        Ok(())
    }

    /// Ensure a specific block is allocated
    async fn ensure_block_allocated(&mut self, block_idx: u64) -> NodeResult<u32> {
        if let Ok(block) = self
            .node
            .get_block_number_for_offset(block_idx * self.node.block_size as u64)
            .await
        {
            return Ok(block);
        }

        // Need to allocate a new block
        let new_block = self.allocator.allocate_block().await?;
        self.set_block_pointer(block_idx, new_block).await?;
        let mut inode = self.node.inode.lock();
        let new_count = block_idx as u32 + 1;
        inode.inode_mut().blocks_count = new_count;
        Ok(new_block)
    }

    /// Set a block pointer (direct, indirect, etc.)
    async fn set_block_pointer(&mut self, block_idx: u64, block: u32) -> NodeResult<()> {
        let mut inode = self.node.inode.lock();
        let inode = inode.inode_mut();

        let ptrs_per_block = self.node.block_size as u64 / 4;

        if block_idx < 12 {
            // Direct block
            inode.blocks[block_idx as usize] = block;
            return Ok(());
        }

        let mut idx = block_idx - 12;

        if idx < ptrs_per_block {
            // Single indirect
            if inode.blocks[12] == 0 {
                inode.blocks[12] = self.allocator.allocate_block().await?;
            }
            self.write_indirect_pointer(inode.blocks[12], idx as u32, block)
                .await?;
            return Ok(());
        }
        idx -= ptrs_per_block;

        if idx < ptrs_per_block * ptrs_per_block {
            // Double indirect
            if inode.blocks[13] == 0 {
                inode.blocks[13] = self.allocator.allocate_block().await?;
            }

            let indirect1 = inode.blocks[13];
            let indirect1_idx = idx / ptrs_per_block;
            let indirect2_idx = idx % ptrs_per_block;

            // Ensure indirect block exists
            let indirect2 = self
                .read_indirect_pointer(indirect1, indirect1_idx as u32)
                .await?;
            let indirect2 = if indirect2 == 0 {
                let new_block = self.allocator.allocate_block().await?;
                self.write_indirect_pointer(indirect1, indirect1_idx as u32, new_block)
                    .await?;
                new_block
            } else {
                indirect2
            };

            self.write_indirect_pointer(indirect2, indirect2_idx as u32, block)
                .await?;
            return Ok(());
        }
        idx -= ptrs_per_block * ptrs_per_block;

        // Triple indirect
        if inode.blocks[14] == 0 {
            inode.blocks[14] = self.allocator.allocate_block().await?;
        }

        let indirect1 = inode.blocks[14];
        let indirect1_idx = idx / (ptrs_per_block * ptrs_per_block);
        let indirect2_idx = (idx / ptrs_per_block) % ptrs_per_block;
        let indirect3_idx = idx % ptrs_per_block;

        // Ensure first level indirect block exists
        let indirect2 = self
            .read_indirect_pointer(indirect1, indirect1_idx as u32)
            .await?;
        let indirect2 = if indirect2 == 0 {
            let new_block = self.allocator.allocate_block().await?;
            self.write_indirect_pointer(indirect1, indirect1_idx as u32, new_block)
                .await?;
            new_block
        } else {
            indirect2
        };

        // Ensure second level indirect block exists
        let indirect3 = self
            .read_indirect_pointer(indirect2, indirect2_idx as u32)
            .await?;
        let indirect3 = if indirect3 == 0 {
            let new_block = self.allocator.allocate_block().await?;
            self.write_indirect_pointer(indirect2, indirect2_idx as u32, new_block)
                .await?;
            new_block
        } else {
            indirect3
        };

        self.write_indirect_pointer(indirect3, indirect3_idx as u32, block)
            .await?;
        Ok(())
    }

    /// Read an indirect block pointer
    async fn read_indirect_pointer(&self, block: u32, index: u32) -> NodeResult<u32> {
        let cached = self
            .node
            .block_cache
            .get(block)
            .await
            .map_err(|_| NodeError::WriteError)?;
        let cached = cached.lock();

        Ok(unsafe { *(cached.data().as_ptr().add(index as usize * 4) as *const u32) })
    }

    /// Write an indirect block pointer
    async fn write_indirect_pointer(&self, block: u32, index: u32, value: u32) -> NodeResult<()> {
        let cached = self
            .node
            .block_cache
            .get(block)
            .await
            .map_err(|_| NodeError::WriteError)?;
        let mut cached = cached.lock();

        unsafe {
            *(cached.data_mut().as_mut_ptr().add(index as usize * 4) as *mut u32) = value;
        }

        Ok(())
    }
}

/// Directory entry with name
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub inode_no: u32,
    pub name: String,
    pub file_type: FileType,
}

/// A node in the filesystem (file, directory, or symlink)
pub struct Node {
    /// Inode number
    number: u32,
    /// Cached inode data
    inode: Arc<Mutex<CachedInode>>,
    /// Block cache reference
    block_cache: Arc<dyn Cache<u32, CachedBlock>>,
    /// Block size
    block_size: u32,
    /// For symlinks: cached target path
    symlink_target: Option<String>,
    allocator: Arc<Allocator>,
}

unsafe impl Send for Node {}
unsafe impl Sync for Node {}

impl Node {
    /// Create a new node
    pub async fn new(
        number: u32,
        inode: Arc<Mutex<CachedInode>>,
        block_cache: Arc<dyn Cache<u32, CachedBlock>>,
        block_size: u32,
        allocator: Arc<Allocator>,
    ) -> Self {
        let mut node = Self {
            number,
            inode,
            block_cache,
            block_size,
            symlink_target: None,
            allocator,
        };

        // Cache symlink target if this is a symlink
        if node.is_symlink() {
            node.symlink_target = Some(node.read_symlink().await.unwrap());
        }

        node
    }

    /// Get the inode number
    pub fn number(&self) -> u32 {
        self.number
    }

    /// Get size in bytes
    pub fn size(&self) -> u64 {
        self.inode.lock().inode().size()
    }

    /// Check if this is a regular file
    pub fn is_file(&self) -> bool {
        self.inode.lock().inode().is_file()
    }

    /// Check if this is a directory
    pub fn is_directory(&self) -> bool {
        self.inode.lock().inode().is_directory()
    }

    /// Check if this is a symbolic link
    pub fn is_symlink(&self) -> bool {
        self.inode.lock().inode().is_symlink()
    }

    /// Get the number of hard links
    pub fn link_count(&self) -> u16 {
        self.inode.lock().inode().links_count
    }

    pub async fn decrease_link_count(&self) -> NodeResult<bool> {
        let mut inode = self.inode.lock();
        let inode = inode.inode_mut();
        inode.links_count -= 1;

        // If no more links, mark for deletion
        if inode.links_count == 0 {
            inode.deletion_time = get_current_time();

            // Free blocks
            for i in 0..inode.blocks_count {
                if let Ok(block) = self
                    .get_block_number_for_offset(i as u64 * self.block_size as u64)
                    .await
                {
                    self.allocator.free_block(block).await?;
                }
            }

            // Free inode
            self.allocator.free_inode(self.number).await?;

            Ok(true) // indicates inode was deleted
        } else {
            Ok(false) // indicates inode still exists
        }
    }

    /// Calculate which block contains the given byte offset
    async fn get_block_number_for_offset(&self, offset: u64) -> NodeResult<u32> {
        let inode = self.inode.lock();
        let inode = inode.inode();

        let block_size = self.block_size as u64;
        let block_index = offset / block_size;

        if block_index < 12 {
            let block_number = inode.blocks[block_index as usize];
            // If block_number is 0, this is a sparse region
            if block_number == 0 {
                return Err(NodeError::InvalidOffset);
            }
            return Ok(block_number);
        }

        let mut remaining = block_index - 12;
        let ptrs_per_block = block_size / 4;

        if remaining < ptrs_per_block {
            if inode.blocks[12] == 0 {
                return Err(NodeError::InvalidOffset);
            }

            let block = self
                .block_cache
                .get(inode.blocks[12])
                .await
                .map_err(|_| NodeError::CacheError)?;
            let block = block.lock();
            let ptr = unsafe { *(block.data().as_ptr().add(remaining as usize * 4) as *const u32) };

            if ptr == 0 {
                return Err(NodeError::InvalidOffset);
            }

            return Ok(ptr);
        }
        remaining -= ptrs_per_block;

        if remaining < ptrs_per_block * ptrs_per_block {
            if inode.blocks[13] == 0 {
                return Err(NodeError::InvalidOffset);
            }

            let index1 = remaining / ptrs_per_block;
            let index2 = remaining % ptrs_per_block;

            let block1 = self
                .block_cache
                .get(inode.blocks[13])
                .await
                .map_err(|_| NodeError::CacheError)?;
            let block1 = block1.lock();
            let ptr1 = unsafe { *(block1.data().as_ptr().add(index1 as usize * 4) as *const u32) };

            if ptr1 == 0 {
                return Err(NodeError::InvalidOffset);
            }

            let block2 = self
                .block_cache
                .get(ptr1)
                .await
                .map_err(|_| NodeError::CacheError)?;
            let block2 = block2.lock();
            let ptr2 = unsafe { *(block2.data().as_ptr().add(index2 as usize * 4) as *const u32) };

            if ptr2 == 0 {
                return Err(NodeError::InvalidOffset);
            }

            return Ok(ptr2);
        }
        remaining -= ptrs_per_block * ptrs_per_block;

        // Check if the triple indirect block is allocated
        if inode.blocks[14] == 0 {
            return Err(NodeError::InvalidOffset);
        }

        let index1 = remaining / (ptrs_per_block * ptrs_per_block);
        let index2 = (remaining / ptrs_per_block) % ptrs_per_block;
        let index3 = remaining % ptrs_per_block;

        let block1 = self
            .block_cache
            .get(inode.blocks[14])
            .await
            .map_err(|_| NodeError::CacheError)?;
        let block1 = block1.lock();
        let ptr1 = unsafe { *(block1.data().as_ptr().add(index1 as usize * 4) as *const u32) };

        if ptr1 == 0 {
            return Err(NodeError::InvalidOffset);
        }

        let block2 = self
            .block_cache
            .get(ptr1)
            .await
            .map_err(|_| NodeError::CacheError)?;
        let block2 = block2.lock();
        let ptr2 = unsafe { *(block2.data().as_ptr().add(index2 as usize * 4) as *const u32) };

        if ptr2 == 0 {
            return Err(NodeError::InvalidOffset);
        }

        let block3 = self
            .block_cache
            .get(ptr2)
            .await
            .map_err(|_| NodeError::CacheError)?;
        let block3 = block3.lock();
        let ptr3 = unsafe { *(block3.data().as_ptr().add(index3 as usize * 4) as *const u32) };

        if ptr3 == 0 {
            return Err(NodeError::InvalidOffset);
        }

        Ok(ptr3)
    }

    async fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> NodeResult<usize> {
        let size = self.size();
        if offset >= size {
            return Ok(0);
        }

        // Clear the entire buffer with zeros before we start reading
        // This ensures sparse regions are properly filled with zeros
        buffer.fill(0);

        let mut bytes_read = 0;
        let mut remaining = min(buffer.len() as u64, size - offset);
        let mut buf_offset = 0;
        let mut file_offset = offset;

        while remaining > 0 {
            // Calculate which block contains this offset
            let block_index = file_offset / self.block_size as u64;

            let block_result = self.get_block_number_for_offset(file_offset).await;
            if let Err(NodeError::InvalidOffset) = block_result {
                // This is a sparse region (block not allocated)
                // Skip to the next allocated block or to the end of the request
                let next_block_index = block_index + 1;
                let next_block_offset = next_block_index * self.block_size as u64;

                let bytes_to_skip = if next_block_offset <= file_offset + remaining {
                    next_block_offset - file_offset
                } else {
                    remaining
                };

                // We've already zeroed the buffer, so just update our counters
                bytes_read += bytes_to_skip;
                buf_offset += bytes_to_skip as usize;
                file_offset += bytes_to_skip;
                remaining -= bytes_to_skip;
                continue;
            }

            let block = block_result?;

            let cached = self
                .block_cache
                .get(block)
                .await
                .map_err(|_| NodeError::CacheError)?;
            let cached = cached.lock();

            let block_offset = file_offset % self.block_size as u64;

            let to_copy = min(remaining, (self.block_size - block_offset as u32) as u64);

            buffer[buf_offset..buf_offset + to_copy as usize]
                .copy_from_slice(&cached.data()[block_offset as usize..][..to_copy as usize]);

            bytes_read += to_copy;
            buf_offset += to_copy as usize;
            file_offset += to_copy;
            remaining -= to_copy;
        }

        Ok(bytes_read as usize)
    }

    /// Read data from the file at the given offset
    pub async fn read_at(&self, offset: u64, buffer: &mut [u8]) -> NodeResult<usize> {
        if !self.is_file() {
            return Err(NodeError::NotFile);
        }
        self.read_raw_at(offset, buffer).await
    }

    /// Read the target of a symbolic link
    async fn read_symlink(&self) -> NodeResult<String> {
        if !self.is_symlink() {
            return Err(NodeError::NotSymlink);
        }

        let inode = self.inode.lock();
        let inode = inode.inode();
        let size = inode.size() as usize;

        // Fast path: target stored in inode blocks array
        if size <= 60 {
            // Create a properly aligned buffer
            let mut buffer = vec![0u8; size];
            let blocks = inode.blocks;

            for (i, byte) in buffer.iter_mut().enumerate().take(size) {
                *byte = unsafe { (&blocks as *const _ as *const u8).add(i).read_unaligned() };
            }

            return Ok(String::from_utf8_lossy(&buffer).into_owned());
        }

        // Regular file path
        let mut buffer = vec![0; size];
        self.read_raw_at(0, &mut buffer)
            .await
            .map_err(|_| NodeError::IoError(BlockError::DeviceError))?;

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    /// Read directory entries
    pub async fn read_dir(&self) -> NodeResult<Vec<DirEntry>> {
        if !self.is_directory() {
            return Err(NodeError::NotDirectory);
        }

        let mut entries = Vec::new();
        let size = self.size();

        if size == 0 {
            return Ok(entries);
        }

        let entry_header_size = size_of::<DirectoryEntry>();
        let mut offset = 0;
        let block_size = self.block_size as u64;

        // Process all entries in the directory
        while offset < size {
            let mut entry = DirectoryEntry {
                inode: 0,
                rec_len: 0,
                name_len: 0,
                file_type: 0,
            };

            // Read entry header
            let bytes_read = self
                .read_raw_at(offset, unsafe {
                    core::slice::from_raw_parts_mut(
                        &mut entry as *mut _ as *mut u8,
                        entry_header_size,
                    )
                })
                .await?;

            if bytes_read < entry_header_size {
                serial_println!("Partial read at offset {}, stopping", offset);
                break;
            }

            // Sanity checks
            if entry.rec_len == 0 {
                serial_println!("Zero rec_len at offset {}, skipping to next block", offset);
                offset = ((offset / block_size) + 1) * block_size;
                continue;
            }

            if entry.inode != 0 {
                let mut name_buffer = vec![0u8; entry.name_len as usize];
                let name_bytes_read = self
                    .read_raw_at(offset + entry_header_size as u64, &mut name_buffer)
                    .await?;

                if name_bytes_read == entry.name_len as usize {
                    let name = String::from_utf8_lossy(&name_buffer).into_owned();

                    entries.push(DirEntry {
                        inode_no: entry.inode,
                        name,
                        file_type: match entry.file_type {
                            1 => FileType::RegularFile,
                            2 => FileType::Directory,
                            7 => FileType::SymbolicLink,
                            _ => FileType::Unknown,
                        },
                    });
                } else {
                    serial_println!("Name read error at offset {}", offset);
                }
            }

            offset += entry.rec_len as u64;
        }

        Ok(entries)
    }

    async fn write_raw_at(&self, offset: u64, buffer: &[u8]) -> NodeResult<usize> {
        let mut ctx = WriteContext::new(self, &self.allocator, offset, buffer.len() as u64);
        ctx.prepare_blocks().await?;
        let mut bytes_written = 0;
        let mut remaining = buffer.len();
        let mut buf_offset = 0;
        let mut file_offset = offset;

        while remaining > 0 {
            let block_offset = file_offset % self.block_size as u64;
            let block = self.get_block_number_for_offset(file_offset).await?;

            let cached = self
                .block_cache
                .get(block)
                .await
                .map_err(|_| NodeError::WriteError)?;
            let mut cached = cached.lock();

            let to_write = min(remaining, (self.block_size - block_offset as u32) as usize);
            cached.data_mut()[block_offset as usize..][..to_write]
                .copy_from_slice(&buffer[buf_offset..][..to_write]);

            bytes_written += to_write;
            buf_offset += to_write;
            file_offset += to_write as u64;
            remaining -= to_write;
        }

        // Update inode size if needed
        let new_size = offset + bytes_written as u64;
        let mut inode = self.inode.lock();
        if new_size > inode.inode().size() {
            inode.inode_mut().size_low = new_size as u32;
        }

        Ok(bytes_written)
    }

    /// Write data to the file at the given offset
    pub async fn write_at(&self, offset: u64, buffer: &[u8]) -> NodeResult<usize> {
        if !self.is_file() {
            return Err(NodeError::NotFile);
        }
        self.write_raw_at(offset, buffer).await
    }

    /// Truncate the file to the given size
    pub async fn truncate(&self, size: u64) -> NodeResult<()> {
        if !self.is_file() {
            return Err(NodeError::NotFile);
        }

        let current_size = self.size();
        if size >= current_size {
            return Ok(());
        }

        // Free unnecessary blocks
        let start_block = size.div_ceil(self.block_size as u64);
        let end_block = current_size.div_ceil(self.block_size as u64);

        for block_idx in start_block..end_block {
            if let Ok(block) = self
                .get_block_number_for_offset(block_idx * self.block_size as u64)
                .await
            {
                self.allocator.free_block(block).await?;
            }
        }

        // Update inode size
        let mut inode = self.inode.lock();
        inode.inode_mut().size_low = size as u32;

        Ok(())
    }

    /// Add a directory entry
    pub async fn add_dir_entry(
        &self,
        name: &str,
        inode_no: u32,
        file_type: FileType,
    ) -> NodeResult<()> {
        if !self.is_directory() {
            return Err(NodeError::NotDirectory);
        }

        if name.len() > 255 {
            return Err(NodeError::NameTooLong);
        }

        // Check if entry already exists
        let entries = self.read_dir().await?;
        if entries.iter().any(|e| e.name == name) {
            return Err(NodeError::AlreadyExists);
        }

        // Calculate sizes
        let entry_header_size = size_of::<DirectoryEntry>();
        let entry_size = entry_header_size + name.len();
        let padded_size = (entry_size + 3) & !3; // Round up to 4-byte alignment

        let dir_size = self.size();
        let block_size = self.block_size as u64;

        // If directory is empty, initialize the first block
        if dir_size == 0 {
            // Allocate first block
            let mut ctx = WriteContext::new(self, &self.allocator, 0, block_size);
            ctx.prepare_blocks().await?;

            // New entry will use the entire block
            let new_entry = DirectoryEntry {
                inode: inode_no,
                rec_len: block_size as u16, // Use entire block
                name_len: name.len() as u8,
                file_type: file_type as u8,
            };

            // Write entry header
            self.write_raw_at(0, unsafe {
                core::slice::from_raw_parts(&new_entry as *const _ as *const u8, entry_header_size)
            })
            .await?;

            // Write name
            self.write_raw_at(entry_header_size as u64, name.as_bytes())
                .await?;

            // Update directory size
            {
                let mut inode = self.inode.lock();
                inode.inode_mut().size_low = entry_size as u32;
            }

            return Ok(());
        }

        // Scan through existing entries to find space
        let mut offset = 0;
        let mut insert_pos = 0;
        let mut found_space = false;

        while offset < dir_size {
            let mut entry = DirectoryEntry {
                inode: 0,
                rec_len: 0,
                name_len: 0,
                file_type: 0,
            };

            // Read current entry
            self.read_raw_at(offset, unsafe {
                core::slice::from_raw_parts_mut(
                    &mut entry as *mut _ as *const u8 as *mut u8,
                    entry_header_size,
                )
            })
            .await?;

            // Check for invalid entries that might cause issues
            if entry.rec_len == 0 {
                offset = ((offset / block_size) + 1) * block_size;
                continue;
            }

            // If entry is deleted, we can reuse its space
            if entry.inode == 0 && entry.rec_len as usize >= padded_size {
                insert_pos = offset;
                found_space = true;
                break;
            }

            let actual_size = entry_header_size + entry.name_len as usize;
            let actual_padded_size = (actual_size + 3) & !3;

            if entry.rec_len as usize > actual_padded_size + 8
                && entry.rec_len as usize - actual_padded_size >= padded_size
            {
                insert_pos = offset + actual_padded_size as u64;

                // Adjust current entry's rec_len
                let mut adjusted_entry = entry;
                adjusted_entry.rec_len = actual_padded_size as u16;

                // Write modified entry
                self.write_raw_at(offset, unsafe {
                    core::slice::from_raw_parts(
                        &adjusted_entry as *const _ as *const u8,
                        entry_header_size,
                    )
                })
                .await?;

                found_space = true;
                break;
            }

            // Move to next entry
            offset += entry.rec_len as u64;
        }

        // If we've reached the end of directory, append at the end
        if !found_space && offset >= dir_size {
            insert_pos = dir_size;

            // Check if we need a new block
            if (insert_pos / block_size) != ((insert_pos + padded_size as u64 - 1) / block_size) {
                // Allocate a new block
                let mut ctx = WriteContext::new(self, &self.allocator, insert_pos, block_size);
                ctx.prepare_blocks().await?;
            }
        }

        // If we still haven't found space, we need to allocate more blocks
        if !found_space && insert_pos == 0 {
            // Allocate new space
            let mut ctx = WriteContext::new(self, &self.allocator, dir_size, padded_size as u64);
            ctx.prepare_blocks().await?;
            insert_pos = dir_size;
        }

        // Calculate rec_len for the new entry
        let block_offset = insert_pos % block_size;
        let remaining_in_block = block_size - block_offset;

        // If this is the last entry in the block, rec_len extends to end of block
        let rec_len = if insert_pos + padded_size as u64 >= dir_size
            && remaining_in_block >= padded_size as u64
        {
            remaining_in_block as u16
        } else {
            padded_size as u16
        };

        // Create new entry
        let new_entry = DirectoryEntry {
            inode: inode_no,
            rec_len,
            name_len: name.len() as u8,
            file_type: file_type as u8,
        };

        // Write entry header
        self.write_raw_at(insert_pos, unsafe {
            core::slice::from_raw_parts(&new_entry as *const _ as *const u8, entry_header_size)
        })
        .await?;

        // Write name
        self.write_raw_at(insert_pos + entry_header_size as u64, name.as_bytes())
            .await?;

        // Update directory size if needed
        let new_dir_size = insert_pos + padded_size as u64;
        if new_dir_size > dir_size {
            let mut inode = self.inode.lock();
            inode.inode_mut().size_low = new_dir_size as u32;
        }

        Ok(())
    }

    /// Remove a directory entry
    pub async fn remove_dir_entry(&self, name: &str) -> NodeResult<()> {
        if !self.is_directory() {
            return Err(NodeError::NotDirectory);
        }

        let mut offset = 0;
        let mut found = false;

        while offset < self.size() {
            let mut entry = DirectoryEntry {
                inode: 0,
                rec_len: 0,
                name_len: 0,
                file_type: 0,
            };

            self.read_raw_at(offset, unsafe {
                core::slice::from_raw_parts_mut(
                    &mut entry as *mut _ as *mut u8,
                    size_of::<DirectoryEntry>(),
                )
            })
            .await?;

            if entry.inode != 0 {
                let mut entry_name = vec![0u8; entry.name_len as usize];
                self.read_raw_at(offset + size_of::<DirectoryEntry>() as u64, &mut entry_name)
                    .await?;

                if name.as_bytes() == entry_name {
                    // Found the entry to remove
                    entry.inode = 0;
                    self.write_raw_at(offset, unsafe {
                        core::slice::from_raw_parts(
                            &entry as *const _ as *const u8,
                            size_of::<DirectoryEntry>(),
                        )
                    })
                    .await?;
                    found = true;
                    break;
                }
            }

            offset += entry.rec_len as u64;
        }

        if !found {
            return Err(NodeError::NotFound);
        }

        Ok(())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // Decrement inode reference count
        self.inode.lock().dec_ref();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            block_io::{BlockIO, MockDevice},
            cache::{block::BlockCache, inode::CachedInode},
            structures::{BlockGroupDescriptor, FileMode, Inode, Superblock},
        },
        *,
    };

    struct TestSetup {
        device: Arc<MockDevice>,
        block_cache: Arc<dyn Cache<u32, CachedBlock>>,
        allocator: Arc<Allocator>,
    }

    impl TestSetup {
        async fn new() -> Self {
            let device = MockDevice::new(1024, 1024 * 1024);
            let device_as_block_io: Arc<dyn BlockIO> = device.clone();
            let block_cache: Arc<dyn Cache<u32, CachedBlock>> =
                Arc::new(BlockCache::new(device_as_block_io, 16));

            let superblock = Arc::new(Superblock {
                block_size_shift: 10, // 1024 bytes
                blocks_per_group: 256,
                inodes_per_group: 64,
                num_blocks: 1024,
                num_inodes: 256,
                ..Default::default()
            });

            let bgdt: Arc<[BlockGroupDescriptor]> =
                Arc::from(vec![BlockGroupDescriptor::new(0, 1, 2, 253, 64, 0)]);

            let allocator = Arc::new(Allocator::new(superblock, bgdt, Arc::clone(&block_cache)));
            // Real file system allocates block 0 for boot sector
            // For us, block 0 shall never be free
            // This is because 0 is used as sentinel to detect unallocated blocks
            allocator.allocate_block().await.unwrap();

            Self {
                device,
                block_cache,
                allocator,
            }
        }

        fn create_inode(&self, mode: u16) -> (u32, Arc<Mutex<CachedInode>>) {
            let inode = Inode {
                mode,
                size_low: 0,
                links_count: 1,
                blocks_count: 0,
                ..Default::default()
            };

            let inode_no = 1;
            let cached = CachedInode::new(inode, inode_no);
            (inode_no, Arc::new(Mutex::new(cached)))
        }

        async fn create_node(&self, mode: u16) -> Arc<Node> {
            let (inode_no, cached_inode) = self.create_inode(mode);
            Arc::new(
                Node::new(
                    inode_no,
                    cached_inode,
                    Arc::clone(&self.block_cache),
                    1024,
                    Arc::clone(&self.allocator),
                )
                .await,
            )
        }
    }

    // Test file operations
    #[test_case]
    async fn test_file_read_write() {
        let setup = TestSetup::new().await;
        let node = setup.create_node(FileMode::REG.bits()).await;

        // Write data
        let data = b"Hello, World!";
        assert_eq!(node.write_at(0, data).await.unwrap(), data.len());

        // Read it back
        let mut buffer = vec![0; data.len()];
        assert_eq!(node.read_at(0, &mut buffer).await.unwrap(), data.len());
        assert_eq!(&buffer, data);

        // Size should be updated
        assert_eq!(node.size(), data.len() as u64);
    }

    #[test_case]
    async fn test_file_append_and_sparse() {
        let setup = TestSetup::new().await;
        let node = setup.create_node(FileMode::REG.bits()).await;

        // Write at offset
        let data = b"Offset data";
        let offset = 1024;
        assert_eq!(node.write_at(offset, data).await.unwrap(), data.len());

        // Read sparse region
        let mut buffer = vec![0; offset as usize];
        assert_eq!(node.read_at(0, &mut buffer).await.unwrap(), offset as usize);
        assert!(buffer.iter().all(|&b| b == 0));

        // Read written data
        let mut buffer = vec![0; data.len()];
        assert_eq!(node.read_at(offset, &mut buffer).await.unwrap(), data.len());
        assert_eq!(&buffer, data);
    }

    #[test_case]
    async fn test_file_truncate() {
        let setup = TestSetup::new().await;
        let node = setup.create_node(FileMode::REG.bits()).await;

        // Write some data
        let data = b"Long data that will be truncated";
        node.write_at(0, data).await.unwrap();

        // Truncate
        let new_size = 10;
        node.truncate(new_size).await.unwrap();
        assert_eq!(node.size(), new_size);

        // Read truncated data
        let mut buffer = vec![0; data.len()];
        let read = node.read_at(0, &mut buffer).await.unwrap();
        assert_eq!(read, new_size as usize);
        assert_eq!(&buffer[..read], &data[..new_size as usize]);
    }

    // Test directory operations
    #[test_case]
    async fn test_directory_entries() {
        let setup = TestSetup::new().await;
        let node = setup.create_node(FileMode::DIR.bits()).await;

        // Add entries
        node.add_dir_entry("file1", 2, FileType::RegularFile)
            .await
            .unwrap();
        node.add_dir_entry("dir1", 3, FileType::Directory)
            .await
            .unwrap();

        // Read entries
        let entries = node.read_dir().await.unwrap();
        assert_eq!(entries.len(), 2);

        let file_entry = entries.iter().find(|e| e.name == "file1").unwrap();
        assert_eq!(file_entry.inode_no, 2);
        assert_eq!(file_entry.file_type, FileType::RegularFile);

        let dir_entry = entries.iter().find(|e| e.name == "dir1").unwrap();
        assert_eq!(dir_entry.inode_no, 3);
        assert_eq!(dir_entry.file_type, FileType::Directory);
    }

    #[test_case]
    async fn test_directory_entry_removal() {
        let setup = TestSetup::new().await;
        let node = setup.create_node(FileMode::DIR.bits()).await;

        // Add and remove entry
        node.add_dir_entry("test", 2, FileType::RegularFile)
            .await
            .unwrap();
        node.remove_dir_entry("test").await.unwrap();

        // Entry should be gone
        let entries = node.read_dir().await.unwrap();
        assert!(!entries.iter().any(|e| e.name == "test"));

        // Removing non-existent entry should fail
        assert!(matches!(
            node.remove_dir_entry("nonexistent").await,
            Err(NodeError::NotFound)
        ));
    }

    // Test symlink operations
    /*#[test_case]
    fn test_symlink() {
        let setup = TestSetup::new();
        let node = setup.create_node(FileMode::LINK.bits());

        // Write target path
        let target = "/path/to/target";
        node.write_at(0, target.as_bytes()).unwrap();

        // Read it back
        let mut buffer = vec![0; target.len()];
        node.read_at(0, &mut buffer).unwrap();
        assert_eq!(String::from_utf8(buffer).unwrap(), target);
    }*/

    // Test block allocation
    #[test_case]
    async fn test_block_allocation() {
        let setup = TestSetup::new().await;
        let node = setup.create_node(FileMode::REG.bits()).await;

        // Write enough data to force block allocation
        let data = vec![42u8; 2048]; // Two blocks worth
        node.write_at(0, &data).await.unwrap();

        // Check blocks were allocated
        let inode = node.inode.lock();
        assert!(inode.inode().blocks_count >= 2);
        assert!(inode.inode().blocks[0] != 0); // Direct block
        assert!(inode.inode().blocks[1] != 0); // Direct block
    }

    #[test_case]
    async fn test_indirect_blocks() {
        let setup = TestSetup::new().await;
        let node = setup.create_node(FileMode::REG.bits()).await;

        // Write enough data to force indirect block allocation
        // 12 direct blocks + some indirect
        let data = vec![42u8; 15 * 1024];
        node.write_at(0, &data).await.unwrap();

        let inode = node.inode.lock();
        assert!(inode.inode().blocks[12] != 0); // Single indirect block
    }

    // Test error conditions
    #[test_case]
    async fn test_error_conditions() {
        let setup = TestSetup::new().await;

        // Try to read directory as file
        let dir_node = setup.create_node(FileMode::DIR.bits()).await;
        let mut buffer = vec![0; 10];
        assert!(matches!(
            dir_node.read_at(0, &mut buffer).await,
            Err(NodeError::NotFile)
        ));

        // Try to read_dir on a file
        let file_node = setup.create_node(FileMode::REG.bits()).await;
        assert!(matches!(
            file_node.read_dir().await,
            Err(NodeError::NotDirectory)
        ));

        // Try to add directory entry to a file
        assert!(matches!(
            file_node
                .add_dir_entry("test", 1, FileType::RegularFile)
                .await,
            Err(NodeError::NotDirectory)
        ));
    }
}
