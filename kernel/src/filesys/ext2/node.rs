use alloc::{string::String, sync::Arc, vec, vec::Vec};
use core::cmp::min;
use spin::Mutex;

use super::{
    block_io::BlockError,
    cache::{block::CachedBlock, inode::CachedInode, Cache},
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
}

pub type NodeResult<T> = Result<T, NodeError>;

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
}

impl Node {
    /// Create a new node
    pub fn new(
        number: u32,
        inode: Arc<Mutex<CachedInode>>,
        block_cache: Arc<dyn Cache<u32, CachedBlock>>,
        block_size: u32,
    ) -> Self {
        let mut node = Self {
            number,
            inode,
            block_cache,
            block_size,
            symlink_target: None,
        };

        // Cache symlink target if this is a symlink
        if node.is_symlink() {
            node.symlink_target = Some(node.read_symlink().unwrap());
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

    /// Calculate which block contains the given byte offset
    fn get_block_number_for_offset(&self, offset: u64) -> NodeResult<u32> {
        let inode = self.inode.lock();
        let inode = inode.inode();

        let block_size = self.block_size as u64;
        let block_index = offset / block_size;

        if block_index >= inode.blocks_count as u64 {
            return Err(NodeError::InvalidOffset);
        }

        // Direct blocks
        if block_index < 12 {
            return Ok(inode.blocks[block_index as usize]);
        }

        // Indirect blocks
        let mut remaining = block_index - 12;
        let ptrs_per_block = block_size / 4;

        // Single indirect
        if remaining < ptrs_per_block {
            let block = self
                .block_cache
                .get(inode.blocks[12])
                .map_err(|_| NodeError::CacheError)?;
            let block = block.lock();
            let ptr = unsafe { *(block.data().as_ptr().add(remaining as usize * 4) as *const u32) };
            return Ok(ptr);
        }
        remaining -= ptrs_per_block;

        // Double indirect
        if remaining < ptrs_per_block * ptrs_per_block {
            let index1 = remaining / ptrs_per_block;
            let index2 = remaining % ptrs_per_block;

            let block1 = self
                .block_cache
                .get(inode.blocks[13])
                .map_err(|_| NodeError::CacheError)?;
            let block1 = block1.lock();
            let ptr1 = unsafe { *(block1.data().as_ptr().add(index1 as usize * 4) as *const u32) };

            let block2 = self
                .block_cache
                .get(ptr1)
                .map_err(|_| NodeError::CacheError)?;
            let block2 = block2.lock();
            let ptr2 = unsafe { *(block2.data().as_ptr().add(index2 as usize * 4) as *const u32) };

            return Ok(ptr2);
        }
        remaining -= ptrs_per_block * ptrs_per_block;

        // Triple indirect
        let index1 = remaining / (ptrs_per_block * ptrs_per_block);
        let index2 = (remaining / ptrs_per_block) % ptrs_per_block;
        let index3 = remaining % ptrs_per_block;

        let block1 = self
            .block_cache
            .get(inode.blocks[14])
            .map_err(|_| NodeError::CacheError)?;
        let block1 = block1.lock();
        let ptr1 = unsafe { *(block1.data().as_ptr().add(index1 as usize * 4) as *const u32) };

        let block2 = self
            .block_cache
            .get(ptr1)
            .map_err(|_| NodeError::CacheError)?;
        let block2 = block2.lock();
        let ptr2 = unsafe { *(block2.data().as_ptr().add(index2 as usize * 4) as *const u32) };

        let block3 = self
            .block_cache
            .get(ptr2)
            .map_err(|_| NodeError::CacheError)?;
        let block3 = block3.lock();
        let ptr3 = unsafe { *(block3.data().as_ptr().add(index3 as usize * 4) as *const u32) };

        Ok(ptr3)
    }

    /// Read data from the file at the given offset
    pub fn read_at(&self, offset: u64, buffer: &mut [u8]) -> NodeResult<usize> {
        if !self.is_file() {
            return Err(NodeError::NotFile);
        }

        let size = self.size();
        if offset >= size {
            return Ok(0);
        }

        let mut bytes_read = 0;
        let mut remaining = min(buffer.len() as u64, size - offset);
        let mut buf_offset = 0;
        let mut file_offset = offset;

        while remaining > 0 {
            let block_offset = file_offset % self.block_size as u64;
            let block = self.get_block_number_for_offset(file_offset)?;

            let cached = self
                .block_cache
                .get(block)
                .map_err(|_| NodeError::CacheError)?;
            let cached = cached.lock();

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

    /// Read the target of a symbolic link
    fn read_symlink(&self) -> NodeResult<String> {
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

            // Copy the blocks data byte by byte to avoid alignment issues
            for i in 0..size {
                buffer[i] = unsafe { (&blocks as *const _ as *const u8).add(i).read_unaligned() };
            }

            return Ok(String::from_utf8_lossy(&buffer).into_owned());
        }

        // Regular file path
        let mut buffer = vec![0; size];
        self.read_at(0, &mut buffer)
            .map_err(|_| NodeError::IoError(BlockError::DeviceError))?;

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    /// Read directory entries
    pub fn read_dir(&self) -> NodeResult<Vec<DirEntry>> {
        if !self.is_directory() {
            return Err(NodeError::NotDirectory);
        }

        let mut entries = Vec::new();
        let size = self.size();
        let mut offset = 0;

        while offset < size {
            let mut entry = DirectoryEntry {
                inode: 0,
                rec_len: 0,
                name_len: 0,
                file_type: 0,
            };

            // Read fixed part of directory entry
            let bytes_read = self.read_at(offset, unsafe {
                core::slice::from_raw_parts_mut(
                    &mut entry as *mut _ as *mut u8,
                    core::mem::size_of::<DirectoryEntry>(),
                )
            })?;

            if bytes_read == 0 || entry.inode == 0 {
                break;
            }

            // Read name
            let mut name = vec![0; entry.name_len as usize];
            self.read_at(
                offset + core::mem::size_of::<DirectoryEntry>() as u64,
                &mut name,
            )?;

            let name = String::from_utf8_lossy(&name).into_owned();

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

            offset += entry.rec_len as u64;
        }

        Ok(entries)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // Decrement inode reference count
        self.inode.lock().dec_ref();
    }
}
