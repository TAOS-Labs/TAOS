use crate::serial_println;
use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::{cmp::min, mem::size_of};
use spin::Mutex;

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
    allocator: &'a Arc<Mutex<Allocator>>,
    offset: u64,
    size: u64,
}

impl<'a> WriteContext<'a> {
    fn new(node: &'a Node, allocator: &'a Arc<Mutex<Allocator>>, offset: u64, size: u64) -> Self {
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

        let new_block = {
            let allocator = self.allocator.lock();
            allocator.allocate_block().await?
        };
        self.set_block_pointer(block_idx, new_block).await?;

        {
            let block_cache = self.node.block_cache.lock();
            let cached_block = block_cache
                .get(new_block)
                .await
                .map_err(|_| NodeError::CacheError)?;

            let mut block_data = cached_block.lock();
            block_data.data_mut().fill(0);
        }

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
            inode.blocks[block_idx as usize] = block;
            return Ok(());
        }

        let mut idx = block_idx - 12;

        if idx < ptrs_per_block {
            if inode.blocks[12] == 0 {
                // Get allocator with lock
                let alloc_block = {
                    let allocator = self.allocator.lock();
                    allocator.allocate_block().await?
                };
                inode.blocks[12] = alloc_block;
            }
            self.write_indirect_pointer(inode.blocks[12], idx as u32, block)
                .await?;
            return Ok(());
        }
        idx -= ptrs_per_block;

        if idx < ptrs_per_block * ptrs_per_block {
            if inode.blocks[13] == 0 {
                let alloc_block = {
                    let allocator = self.allocator.lock();
                    allocator.allocate_block().await?
                };
                inode.blocks[13] = alloc_block;
            }

            let indirect1 = inode.blocks[13];
            let indirect1_idx = idx / ptrs_per_block;
            let indirect2_idx = idx % ptrs_per_block;

            let indirect2 = self
                .read_indirect_pointer(indirect1, indirect1_idx as u32)
                .await?;
            let indirect2 = if indirect2 == 0 {
                // Get allocator with lock
                let new_block = {
                    let allocator = self.allocator.lock();
                    allocator.allocate_block().await?
                };
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

        if inode.blocks[14] == 0 {
            let alloc_block = {
                let allocator = self.allocator.lock();
                allocator.allocate_block().await?
            };
            inode.blocks[14] = alloc_block;
        }

        let indirect1 = inode.blocks[14];
        let indirect1_idx = idx / (ptrs_per_block * ptrs_per_block);
        let indirect2_idx = (idx / ptrs_per_block) % ptrs_per_block;
        let indirect3_idx = idx % ptrs_per_block;

        let indirect2 = self
            .read_indirect_pointer(indirect1, indirect1_idx as u32)
            .await?;
        let indirect2 = if indirect2 == 0 {
            let new_block = {
                let allocator = self.allocator.lock();
                allocator.allocate_block().await?
            };
            self.write_indirect_pointer(indirect1, indirect1_idx as u32, new_block)
                .await?;
            new_block
        } else {
            indirect2
        };

        let indirect3 = self
            .read_indirect_pointer(indirect2, indirect2_idx as u32)
            .await?;
        let indirect3 = if indirect3 == 0 {
            // Get allocator with lock
            let new_block = {
                let allocator = self.allocator.lock();
                allocator.allocate_block().await?
            };
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
        let block_cache = self.node.block_cache.lock();
        let cached_block = block_cache
            .get(block)
            .await
            .map_err(|_| NodeError::WriteError)?;

        let cached = cached_block.lock();

        Ok(unsafe { *(cached.data().as_ptr().add(index as usize * 4) as *const u32) })
    }

    /// Write an indirect block pointer
    async fn write_indirect_pointer(&self, block: u32, index: u32, value: u32) -> NodeResult<()> {
        let block_cache = self.node.block_cache.lock();
        let cached_block = block_cache
            .get(block)
            .await
            .map_err(|_| NodeError::WriteError)?;

        let mut cached = cached_block.lock();

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
    block_cache: Arc<Mutex<Box<dyn Cache<u32, CachedBlock>>>>,
    /// Block size
    block_size: u32,
    /// For symlinks: cached target path
    symlink_target: Option<String>,
    allocator: Arc<Mutex<Allocator>>,
}

impl Node {
    /// Create a new node
    pub async fn new(
        number: u32,
        inode: Arc<Mutex<CachedInode>>,
        block_cache: Arc<Mutex<Box<dyn Cache<u32, CachedBlock>>>>,
        block_size: u32,
        allocator: Arc<Mutex<Allocator>>,
    ) -> Self {
        let mut node = Self {
            number,
            inode,
            block_cache,
            block_size,
            symlink_target: None,
            allocator,
        };

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
        let (links_count, _, file_size) = {
            let mut inode_guard = self.inode.lock();
            let inode = inode_guard.inode_mut();
            inode.links_count -= 1;

            let links = inode.links_count;
            let blocks = inode.blocks_count;
            let size = inode.size();

            if links == 0 {
                inode.deletion_time = get_current_time();
            }

            (links, blocks, size)
        };

        if links_count == 0 {
            let block_size = self.block_size as u64;
            let total_blocks = file_size.div_ceil(block_size);

            for i in 0..total_blocks {
                if let Ok(block) = self.get_block_number_for_offset(i * block_size).await {
                    let allocator = self.allocator.lock();
                    if let Err(e) = allocator.free_block(block).await {
                        serial_println!("Error freeing block {}: {:?}", block, e);
                    }
                }
            }

            {
                let allocator = self.allocator.lock();
                allocator.free_inode(self.number).await?;
            }

            Ok(true)
        } else {
            Ok(false)
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

            let block_cache = self.block_cache.lock();
            let cached_block = block_cache
                .get(inode.blocks[12])
                .await
                .map_err(|_| NodeError::CacheError)?;

            let block = cached_block.lock();
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

            let block_cache = self.block_cache.lock();
            let cached_block1 = block_cache
                .get(inode.blocks[13])
                .await
                .map_err(|_| NodeError::CacheError)?;

            let block1 = cached_block1.lock();
            let ptr1 = unsafe { *(block1.data().as_ptr().add(index1 as usize * 4) as *const u32) };

            if ptr1 == 0 {
                return Err(NodeError::InvalidOffset);
            }

            let cached_block2 = block_cache
                .get(ptr1)
                .await
                .map_err(|_| NodeError::CacheError)?;

            let block2 = cached_block2.lock();
            let ptr2 = unsafe { *(block2.data().as_ptr().add(index2 as usize * 4) as *const u32) };

            if ptr2 == 0 {
                return Err(NodeError::InvalidOffset);
            }

            return Ok(ptr2);
        }
        remaining -= ptrs_per_block * ptrs_per_block;

        if inode.blocks[14] == 0 {
            return Err(NodeError::InvalidOffset);
        }

        let index1 = remaining / (ptrs_per_block * ptrs_per_block);
        let index2 = (remaining / ptrs_per_block) % ptrs_per_block;
        let index3 = remaining % ptrs_per_block;

        let block_cache = self.block_cache.lock();

        let cached_block1 = block_cache
            .get(inode.blocks[14])
            .await
            .map_err(|_| NodeError::CacheError)?;

        let block1 = cached_block1.lock();
        let ptr1 = unsafe { *(block1.data().as_ptr().add(index1 as usize * 4) as *const u32) };

        if ptr1 == 0 {
            return Err(NodeError::InvalidOffset);
        }

        let cached_block2 = block_cache
            .get(ptr1)
            .await
            .map_err(|_| NodeError::CacheError)?;

        let block2 = cached_block2.lock();
        let ptr2 = unsafe { *(block2.data().as_ptr().add(index2 as usize * 4) as *const u32) };

        if ptr2 == 0 {
            return Err(NodeError::InvalidOffset);
        }

        let cached_block3 = block_cache
            .get(ptr2)
            .await
            .map_err(|_| NodeError::CacheError)?;

        let block3 = cached_block3.lock();
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

        buffer.fill(0);

        let mut bytes_read = 0;
        let mut remaining = min(buffer.len() as u64, size - offset);
        let mut buf_offset = 0;
        let mut file_offset = offset;

        while remaining > 0 {
            let block_index = file_offset / self.block_size as u64;

            let block_result = self.get_block_number_for_offset(file_offset).await;
            if let Err(NodeError::InvalidOffset) = block_result {
                let next_block_index = block_index + 1;
                let next_block_offset = next_block_index * self.block_size as u64;

                let bytes_to_skip = if next_block_offset <= file_offset + remaining {
                    next_block_offset - file_offset
                } else {
                    remaining
                };

                bytes_read += bytes_to_skip;
                buf_offset += bytes_to_skip as usize;
                file_offset += bytes_to_skip;
                remaining -= bytes_to_skip;
                continue;
            }

            let block = block_result?;

            let block_cache = self.block_cache.lock();
            let cached_block = block_cache
                .get(block)
                .await
                .map_err(|_| NodeError::CacheError)?;

            let cached = cached_block.lock();
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

        while offset < size {
            let mut entry = DirectoryEntry {
                inode: 0,
                rec_len: 0,
                name_len: 0,
                file_type: 0,
            };

            let bytes_read = self
                .read_raw_at(offset, unsafe {
                    core::slice::from_raw_parts_mut(
                        &mut entry as *mut _ as *mut u8,
                        entry_header_size,
                    )
                })
                .await?;

            if bytes_read < entry_header_size {
                break;
            }

            // Sanity checks
            if entry.rec_len == 0 {
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

            let block_cache = self.block_cache.lock();
            let cached_block = block_cache
                .get(block)
                .await
                .map_err(|_| NodeError::WriteError)?;

            let mut cached = cached_block.lock();

            let to_write = min(remaining, (self.block_size - block_offset as u32) as usize);
            cached.data_mut()[block_offset as usize..][..to_write]
                .copy_from_slice(&buffer[buf_offset..][..to_write]);

            bytes_written += to_write;
            buf_offset += to_write;
            file_offset += to_write as u64;
            remaining -= to_write;
        }

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

        let start_block = size.div_ceil(self.block_size as u64);
        let end_block = current_size.div_ceil(self.block_size as u64);

        for block_idx in start_block..end_block {
            if let Ok(block) = self
                .get_block_number_for_offset(block_idx * self.block_size as u64)
                .await
            {
                let allocator = self.allocator.lock();
                allocator.free_block(block).await?;
            }
        }

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

        let entries = self.read_dir().await?;
        if entries.iter().any(|e| e.name == name) {
            return Err(NodeError::AlreadyExists);
        }

        let entry_header_size = size_of::<DirectoryEntry>();
        let entry_size = entry_header_size + name.len();
        let padded_size = (entry_size + 3) & !3; // Round up to 4-byte alignment

        let dir_size = self.size();
        let block_size = self.block_size as u64;

        if dir_size == 0 {
            let mut ctx = WriteContext::new(self, &self.allocator, 0, block_size);
            ctx.prepare_blocks().await?;

            let new_entry = DirectoryEntry {
                inode: inode_no,
                rec_len: block_size as u16, // Use entire block
                name_len: name.len() as u8,
                file_type: file_type as u8,
            };

            self.write_raw_at(0, unsafe {
                core::slice::from_raw_parts(&new_entry as *const _ as *const u8, entry_header_size)
            })
            .await?;

            self.write_raw_at(entry_header_size as u64, name.as_bytes())
                .await?;

            {
                let mut inode = self.inode.lock();
                inode.inode_mut().size_low = entry_size as u32;
            }

            return Ok(());
        }

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

            self.read_raw_at(offset, unsafe {
                core::slice::from_raw_parts_mut(&mut entry as *mut _ as *mut u8, entry_header_size)
            })
            .await?;

            if entry.rec_len == 0 {
                offset = ((offset / block_size) + 1) * block_size;
                continue;
            }

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

                let mut adjusted_entry = entry;
                adjusted_entry.rec_len = actual_padded_size as u16;

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

            offset += entry.rec_len as u64;
        }

        if !found_space && offset >= dir_size {
            insert_pos = dir_size;

            if (insert_pos / block_size) != ((insert_pos + padded_size as u64 - 1) / block_size) {
                let mut ctx = WriteContext::new(self, &self.allocator, insert_pos, block_size);
                ctx.prepare_blocks().await?;
            }
        }

        if !found_space && insert_pos == 0 {
            let mut ctx = WriteContext::new(self, &self.allocator, dir_size, padded_size as u64);
            ctx.prepare_blocks().await?;
            insert_pos = dir_size;
        }

        let block_offset = insert_pos % block_size;
        let remaining_in_block = block_size - block_offset;

        let rec_len = if insert_pos + padded_size as u64 >= dir_size
            && remaining_in_block >= padded_size as u64
        {
            remaining_in_block as u16
        } else {
            padded_size as u16
        };

        let new_entry = DirectoryEntry {
            inode: inode_no,
            rec_len,
            name_len: name.len() as u8,
            file_type: file_type as u8,
        };

        self.write_raw_at(insert_pos, unsafe {
            core::slice::from_raw_parts(&new_entry as *const _ as *const u8, entry_header_size)
        })
        .await?;

        self.write_raw_at(insert_pos + entry_header_size as u64, name.as_bytes())
            .await?;

        let new_dir_size = insert_pos + padded_size as u64;
        if new_dir_size > dir_size {
            let mut inode = self.inode.lock();
            inode.inode_mut().size_low = new_dir_size as u32;
        }

        Ok(())
    }

    pub async fn remove_dir_entry(&self, name: &str) -> NodeResult<()> {
        if !self.is_directory() {
            return Err(NodeError::NotDirectory);
        }

        let mut offset = 0;
        let mut found = false;
        let dir_size = self.size();

        let block_size = self.block_size as u64;
        let max_entries = dir_size.div_ceil(block_size) * (block_size / 8); // Rough estimate
        let mut entry_count = 0;

        while offset < dir_size && entry_count < max_entries {
            entry_count += 1;

            let mut entry = DirectoryEntry {
                inode: 0,
                rec_len: 0,
                name_len: 0,
                file_type: 0,
            };
            let entry_header_size = size_of::<DirectoryEntry>();

            let bytes_read = self
                .read_raw_at(offset, unsafe {
                    core::slice::from_raw_parts_mut(
                        &mut entry as *mut _ as *mut u8,
                        entry_header_size,
                    )
                })
                .await?;

            if bytes_read < entry_header_size || entry.rec_len == 0 {
                offset = ((offset / block_size) + 1) * block_size;
                continue;
            }

            if entry.inode != 0 {
                let mut entry_name = vec![0u8; entry.name_len as usize];
                let name_bytes_read = self
                    .read_raw_at(offset + entry_header_size as u64, &mut entry_name)
                    .await?;

                if name_bytes_read == entry.name_len as usize
                    && String::from_utf8_lossy(&entry_name) == name
                {
                    entry.inode = 0;

                    self.write_raw_at(offset, unsafe {
                        core::slice::from_raw_parts(
                            &entry as *const _ as *const u8,
                            entry_header_size,
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
        self.inode.lock().dec_ref();
    }
}

#[cfg(test)]
mod tests {
    use spin::RwLock;

    use super::{
        super::{
            block_io::{BlockIO, MockDevice},
            cache::{block::BlockCache, inode::CachedInode},
            structures::{BlockGroupDescriptor, FileMode, Inode, Superblock},
        },
        *,
    };

    struct TestSetup {
        _device: Arc<MockDevice>,
        block_cache: Arc<Mutex<Box<dyn Cache<u32, CachedBlock>>>>,
        allocator: Arc<Mutex<Allocator>>,
    }

    impl TestSetup {
        async fn new() -> Self {
            let device = Arc::new(MockDevice::new(1024, 1024 * 1024));
            let device_as_block_io: Arc<dyn BlockIO> = device.clone();
            let block_cache = Arc::new(Mutex::new(
                Box::new(BlockCache::new(device_as_block_io, 16))
                    as Box<dyn Cache<u32, CachedBlock>>,
            ));

            let superblock = Arc::new(RwLock::new(Superblock {
                block_size_shift: 10,
                blocks_per_group: 256,
                inodes_per_group: 64,
                num_blocks: 1024,
                num_inodes: 256,
                ..Default::default()
            }));

            let bgdt = Arc::new(RwLock::new(vec![BlockGroupDescriptor::new(
                0, 1, 2, 253, 64, 0,
            )]));

            let allocator = Arc::new(Mutex::new(Allocator::new(
                Arc::clone(&superblock),
                Arc::clone(&bgdt),
                Arc::clone(&block_cache),
            )));

            // Real file system allocates block 0 for boot sector
            // For us, block 0 shall never be free
            // This is because 0 is used as sentinel to detect unallocated blocks
            {
                let alloc = allocator.lock();
                alloc.allocate_block().await.unwrap();
            }

            Self {
                _device: device,
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

        let data = b"Hello, World!";
        assert_eq!(node.write_at(0, data).await.unwrap(), data.len());

        let mut buffer = vec![0; data.len()];
        assert_eq!(node.read_at(0, &mut buffer).await.unwrap(), data.len());
        assert_eq!(&buffer, data);

        assert_eq!(node.size(), data.len() as u64);
    }

    #[test_case]
    async fn test_file_append_and_sparse() {
        let setup = TestSetup::new().await;
        let node = setup.create_node(FileMode::REG.bits()).await;

        let data = b"Offset data";
        let offset = 1024;
        assert_eq!(node.write_at(offset, data).await.unwrap(), data.len());

        let mut buffer = vec![0; offset as usize];
        assert_eq!(node.read_at(0, &mut buffer).await.unwrap(), offset as usize);
        assert!(buffer.iter().all(|&b| b == 0));

        let mut buffer = vec![0; data.len()];
        assert_eq!(node.read_at(offset, &mut buffer).await.unwrap(), data.len());
        assert_eq!(&buffer, data);
    }

    #[test_case]
    async fn test_file_truncate() {
        let setup = TestSetup::new().await;
        let node = setup.create_node(FileMode::REG.bits()).await;

        let data = b"Long data that will be truncated";
        node.write_at(0, data).await.unwrap();

        let new_size = 10;
        node.truncate(new_size).await.unwrap();
        assert_eq!(node.size(), new_size);

        let mut buffer = vec![0; data.len()];
        let read = node.read_at(0, &mut buffer).await.unwrap();
        assert_eq!(read, new_size as usize);
        assert_eq!(&buffer[..read], &data[..new_size as usize]);
    }

    #[test_case]
    async fn test_directory_entries() {
        let setup = TestSetup::new().await;
        let node = setup.create_node(FileMode::DIR.bits()).await;

        node.add_dir_entry("file1", 2, FileType::RegularFile)
            .await
            .unwrap();
        node.add_dir_entry("dir1", 3, FileType::Directory)
            .await
            .unwrap();

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

        node.add_dir_entry("test", 2, FileType::RegularFile)
            .await
            .unwrap();
        node.remove_dir_entry("test").await.unwrap();

        let entries = node.read_dir().await.unwrap();
        assert!(!entries.iter().any(|e| e.name == "test"));

        assert!(matches!(
            node.remove_dir_entry("nonexistent").await,
            Err(NodeError::NotFound)
        ));
    }

    #[test_case]
    async fn test_block_allocation() {
        let setup = TestSetup::new().await;
        let node = setup.create_node(FileMode::REG.bits()).await;

        let data = vec![42u8; 2048]; // Two blocks worth
        node.write_at(0, &data).await.unwrap();

        let inode = node.inode.lock();
        assert!(inode.inode().blocks_count >= 2);
        assert!(inode.inode().blocks[0] != 0); // Direct block
        assert!(inode.inode().blocks[1] != 0); // Direct block
    }

    #[test_case]
    async fn test_indirect_blocks() {
        let setup = TestSetup::new().await;
        let node = setup.create_node(FileMode::REG.bits()).await;

        let data = vec![42u8; 15 * 1024];
        node.write_at(0, &data).await.unwrap();

        let inode = node.inode.lock();
        assert!(inode.inode().blocks[12] != 0); // Single indirect block
    }

    #[test_case]
    async fn test_error_conditions() {
        let setup = TestSetup::new().await;

        let dir_node = setup.create_node(FileMode::DIR.bits()).await;
        let mut buffer = vec![0; 10];
        assert!(matches!(
            dir_node.read_at(0, &mut buffer).await,
            Err(NodeError::NotFile)
        ));

        let file_node = setup.create_node(FileMode::REG.bits()).await;
        assert!(matches!(
            file_node.read_dir().await,
            Err(NodeError::NotDirectory)
        ));

        assert!(matches!(
            file_node
                .add_dir_entry("test", 1, FileType::RegularFile)
                .await,
            Err(NodeError::NotDirectory)
        ));
    }
}
