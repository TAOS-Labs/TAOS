use alloc::{sync::Arc, vec, vec::Vec, string::String};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::{
    allocator::Allocator,
    block_io::{BlockError, BlockIO},
    cache::{block::CachedBlock, BlockCache, Cache, CacheStats, InodeCache},
    node::{DirEntry, Node, NodeError},
    structures::{BlockGroupDescriptor, Superblock, EXT2_SIGNATURE, FileMode, FileType},
    get_current_time,
};

/// Error types for filesystem operations
#[derive(Debug)]
pub enum FilesystemError {
    /// Invalid superblock (bad signature or version)
    InvalidSuperblock,
    /// Error reading from device
    DeviceError(BlockError),
    /// Error in node operations
    NodeError(NodeError),
    /// Filesystem is not mounted
    NotMounted,
    /// Path not found
    NotFound,
    /// Invalid path (empty or malformed)
    InvalidPath,
    CacheError,
}

pub type FilesystemResult<T> = Result<T, FilesystemError>;

/// Main Ext2 filesystem structure
pub struct Ext2 {
    /// The underlying block device
    device: Arc<dyn BlockIO>,
    /// Superblock
    superblock: Arc<Superblock>,
    /// Block group descriptors
    bgdt: Arc<[BlockGroupDescriptor]>,
    /// Block cache
    block_cache: Arc<dyn Cache<u32, CachedBlock>>,
    /// Inode cache
    inode_cache: Arc<InodeCache>,
    /// Root directory node
    root: Arc<Mutex<Option<Arc<Node>>>>,
    /// Mounted flag
    mounted: AtomicBool,
    allocator: Arc<Allocator>,
}

impl Ext2 {
    /// Create a new Ext2 filesystem instance
    ///
    /// # Arguments
    /// * `device` - The block device containing the filesystem
    pub fn new(device: Arc<dyn BlockIO>) -> Arc<Self> {
        let superblock = Arc::new(Superblock::default());
        let bgdt: Arc<[BlockGroupDescriptor]> = Arc::new([]);

        let block_cache: Arc<dyn Cache<u32, CachedBlock>> =
            Arc::new(BlockCache::new(Arc::clone(&device), 1024));

        let allocator = Arc::new(Allocator::new(
            Arc::clone(&superblock),
            Arc::clone(&bgdt),
            Arc::clone(&block_cache),
        ));

        let inode_cache = Arc::new(InodeCache::new(
            Arc::clone(&device),
            Arc::clone(&superblock),
            Arc::clone(&bgdt),
            Arc::clone(&block_cache),
            1024,
        ));

        Arc::new(Self {
            device,
            superblock,
            bgdt,
            block_cache,
            inode_cache,
            root: Arc::new(Mutex::new(None)),
            mounted: AtomicBool::new(false),
            allocator,
        })
    }

    /// Mount the filesystem, reading superblock and preparing caches
    /// Mount the filesystem, reading superblock and preparing caches
    pub fn mount(&self) -> FilesystemResult<()> {
        if self.mounted.load(Ordering::Acquire) {
            return Ok(());
        }

        // Read superblock
        let mut superblock = Superblock::default();
        unsafe {
            self.device
                .read_block(
                    2,
                    core::slice::from_raw_parts_mut(
                        &mut superblock as *mut _ as *mut u8,
                        core::mem::size_of::<Superblock>(),
                    ),
                )
                .map_err(FilesystemError::DeviceError)?;
        }

        // Verify superblock
        if superblock.signature != EXT2_SIGNATURE {
            return Err(FilesystemError::InvalidSuperblock);
        }

        // Calculate number of block groups
        let block_groups = superblock.block_group_count();

        // Read block group descriptors
        let mut bgdt = Vec::with_capacity(block_groups as usize);
        let bgdt_start = if superblock.block_size() == 1024 {
            2
        } else {
            1
        };

        for i in 0..block_groups {
            let mut desc = BlockGroupDescriptor::default();
            unsafe {
                self.device
                    .read_block(
                        bgdt_start + i,
                        core::slice::from_raw_parts_mut(
                            &mut desc as *mut _ as *mut u8,
                            core::mem::size_of::<BlockGroupDescriptor>(),
                        ),
                    )
                    .map_err(FilesystemError::DeviceError)?;
            }
            bgdt.push(desc);
        }

        // Update filesystem structures
        let superblock = Arc::new(superblock);
        let bgdt: Arc<[BlockGroupDescriptor]> = Arc::from(bgdt.into_boxed_slice());

        // Create caches with proper sizes
        let block_cache: Arc<dyn Cache<u32, CachedBlock>> = Arc::new(BlockCache::new(
            Arc::clone(&self.device),
            1024, // Configurable cache size
        ));

        let inode_cache = Arc::new(InodeCache::new(
            Arc::clone(&self.device),
            Arc::clone(&superblock),
            Arc::clone(&bgdt),
            Arc::clone(&block_cache),
            1024, // Configurable cache size
        ));

        // Load root inode (always inode 2 in ext2)
        let root_inode = inode_cache
            .get(2)
            .map_err(|_| FilesystemError::CacheError)?;

        let root_node = Arc::new(Node::new(
            2,
            root_inode,
            Arc::clone(&self.block_cache),
            superblock.block_size(),
            Arc::clone(&self.allocator), // Pass allocator reference
        ));

        // Update self
        unsafe {
            let this = self as *const _ as *mut Self;
            (*this).superblock = superblock;
            (*this).bgdt = bgdt;
            (*this).block_cache = block_cache;
            (*this).inode_cache = inode_cache;
            (*this).root = Arc::new(Mutex::new(Some(root_node)));
        }

        self.mounted.store(true, Ordering::Release);
        Ok(())
    }

    /// Unmount the filesystem
    pub fn unmount(&self) -> FilesystemResult<()> {
        if !self.mounted.load(Ordering::Acquire) {
            return Ok(());
        }

        // Clear caches
        self.inode_cache
            .clear()
            .map_err(|_| FilesystemError::CacheError)?;
        self.block_cache
            .clear()
            .map_err(|_| FilesystemError::CacheError)?;

        // Clear root
        *self.root.lock() = None;

        self.mounted.store(false, Ordering::Release);
        Ok(())
    }

    /// Get a node by path
    pub fn get_node(&self, path: &str) -> FilesystemResult<Arc<Node>> {
        if !self.mounted.load(Ordering::Acquire) {
            return Err(FilesystemError::NotMounted);
        }

        if path.is_empty() {
            return Err(FilesystemError::InvalidPath);
        }

        let root = self
            .root
            .lock()
            .as_ref()
            .ok_or(FilesystemError::NotMounted)?
            .clone();

        if path == "/" {
            return Ok(root);
        }

        let mut current = root;
        for component in path.split('/').filter(|s| !s.is_empty()) {
            let entries = current.read_dir().map_err(FilesystemError::NodeError)?;

            let entry = entries
                .iter()
                .find(|e| e.name == component)
                .ok_or(FilesystemError::NotFound)?;

            let inode = self
                .inode_cache
                .get(entry.inode_no)
                .map_err(|_| FilesystemError::CacheError)?;

            current = Arc::new(Node::new(
                entry.inode_no,
                inode,
                Arc::clone(&self.block_cache),
                self.superblock.block_size(),
                Arc::clone(&self.allocator),
            ));
        }

        Ok(current)
    }

    /// Read all entries in a directory
    pub fn read_dir(&self, path: &str) -> FilesystemResult<Vec<DirEntry>> {
        let node = self.get_node(path)?;
        node.read_dir().map_err(FilesystemError::NodeError)
    }

    /// Read file contents
    pub fn read_file(&self, path: &str) -> FilesystemResult<Vec<u8>> {
        let node = self.get_node(path)?;
        if !node.is_file() {
            return Err(FilesystemError::NodeError(NodeError::NotFile));
        }

        let size = node.size() as usize;
        let mut buffer = vec![0; size];
        node.read_at(0, &mut buffer)
            .map_err(|e| FilesystemError::NodeError(e))?;

        Ok(buffer)
    }

    /// Get filesystem statistics
    pub fn stats(&self) -> FilesystemResult<FilesystemStats> {
        if !self.mounted.load(Ordering::Acquire) {
            return Err(FilesystemError::NotMounted);
        }

        Ok(FilesystemStats {
            block_size: self.superblock.block_size(),
            total_blocks: self.superblock.num_blocks,
            free_blocks: self.superblock.num_unallocated_blocks,
            total_inodes: self.superblock.num_inodes,
            free_inodes: self.superblock.num_unallocated_inodes,
            block_cache_stats: self.block_cache.stats(),
            inode_cache_stats: self.inode_cache.stats(),
        })
    }

    /// Create a new file
    pub fn create_file(&self, path: &str, mode: FileMode) -> FilesystemResult<Arc<Node>> {
        if !self.mounted.load(Ordering::Acquire) {
            return Err(FilesystemError::NotMounted);
        }

        // Split path into parent directory and filename
        let (parent_path, name) = match path.rfind('/') {
            Some(idx) => (&path[..idx], &path[idx + 1..]),
            None => ("/", path),
        };

        if name.is_empty() || name.len() > 255 {
            return Err(FilesystemError::InvalidPath);
        }

        // Get parent directory
        let parent = self.get_node(parent_path)?;
        if !parent.is_directory() {
            return Err(FilesystemError::NodeError(NodeError::NotDirectory));
        }

        // Check if file already exists
        if let Ok(_) = self.get_node(path) {
            return Err(FilesystemError::NodeError(NodeError::AlreadyExists));
        }

        // Allocate new inode
        let inode_no = self
            .allocator
            .allocate_inode()
            .map_err(|e| FilesystemError::NodeError(e.into()))?;

        // Initialize inode
        let inode = self
            .inode_cache
            .get(inode_no)
            .map_err(|_| FilesystemError::CacheError)?;
        {
            let mut inode = inode.lock();
            let inode = inode.inode_mut();
            inode.mode = mode.bits();
            inode.size_low = 0;
            inode.links_count = 1;
            inode.blocks_count = 0;
            inode.flags = 0;
            // Set timestamps
            let now = get_current_time();
            inode.creation_time = now;
            inode.modification_time = now;
            inode.access_time = now;
        }

        // Add directory entry in parent
        parent
            .add_dir_entry(name, inode_no, FileType::RegularFile)
            .map_err(FilesystemError::NodeError)?;

        // Create and return node
        let node = Arc::new(Node::new(
            inode_no,
            inode,
            Arc::clone(&self.block_cache),
            self.superblock.block_size(),
            Arc::clone(&self.allocator),
        ));

        Ok(node)
    }

    /// Create a new directory
    pub fn create_directory(&self, path: &str, mode: FileMode) -> FilesystemResult<Arc<Node>> {
        if !self.mounted.load(Ordering::Acquire) {
            return Err(FilesystemError::NotMounted);
        }

        // Split path into parent directory and name
        let (parent_path, name) = match path.rfind('/') {
            Some(idx) => (&path[..idx], &path[idx + 1..]),
            None => ("/", path),
        };

        if name.is_empty() || name.len() > 255 {
            return Err(FilesystemError::InvalidPath);
        }

        // Get parent directory
        let parent = self.get_node(parent_path)?;
        if !parent.is_directory() {
            return Err(FilesystemError::NodeError(NodeError::NotDirectory));
        }

        // Check if directory already exists
        if let Ok(_) = self.get_node(path) {
            return Err(FilesystemError::NodeError(NodeError::AlreadyExists));
        }

        // Allocate new inode
        let inode_no = self
            .allocator
            .allocate_inode()
            .map_err(|e| FilesystemError::NodeError(e.into()))?;

        // Initialize inode
        let inode = self
            .inode_cache
            .get(inode_no)
            .map_err(|_| FilesystemError::CacheError)?;
        {
            let mut inode = inode.lock();
            let inode = inode.inode_mut();
            inode.mode = mode.bits() | FileMode::DIR.bits();
            inode.size_low = 0;
            inode.links_count = 2; // . and ..
            inode.blocks_count = 0;
            inode.flags = 0;
            let now = get_current_time();
            inode.creation_time = now;
            inode.modification_time = now;
            inode.access_time = now;
        }

        // Create directory node
        let node = Arc::new(Node::new(
            inode_no,
            inode,
            Arc::clone(&self.block_cache),
            self.superblock.block_size(),
            Arc::clone(&self.allocator),
        ));

        // Add . and .. entries
        node.add_dir_entry(".", inode_no, FileType::Directory)
            .map_err(FilesystemError::NodeError)?;
        node.add_dir_entry("..", parent.number(), FileType::Directory)
            .map_err(FilesystemError::NodeError)?;

        // Add entry in parent directory
        parent
            .add_dir_entry(name, inode_no, FileType::Directory)
            .map_err(FilesystemError::NodeError)?;

        Ok(node)
    }

    /// Create a symbolic link
    pub fn create_symlink(&self, path: &str, target: &str) -> FilesystemResult<Arc<Node>> {
        if !self.mounted.load(Ordering::Acquire) {
            return Err(FilesystemError::NotMounted);
        }

        // Split path into parent directory and name
        let (parent_path, name) = match path.rfind('/') {
            Some(idx) => (&path[..idx], &path[idx + 1..]),
            None => ("/", path),
        };

        if name.is_empty() || name.len() > 255 {
            return Err(FilesystemError::InvalidPath);
        }

        // Get parent directory
        let parent = self.get_node(parent_path)?;
        if !parent.is_directory() {
            return Err(FilesystemError::NodeError(NodeError::NotDirectory));
        }

        // Check if link already exists
        if let Ok(_) = self.get_node(path) {
            return Err(FilesystemError::NodeError(NodeError::AlreadyExists));
        }

        // Allocate new inode
        let inode_no = self
            .allocator
            .allocate_inode()
            .map_err(|e| FilesystemError::NodeError(e.into()))?;

        // Initialize inode
        let inode = self
            .inode_cache
            .get(inode_no)
            .map_err(|_| FilesystemError::CacheError)?;
        {
            let mut inode = inode.lock();
            let inode = inode.inode_mut();
            inode.mode = FileMode::LINK.bits();
            inode.size_low = target.len() as u32;
            inode.links_count = 1;
            inode.blocks_count = 0;
            inode.flags = 0;
            let now = get_current_time();
            inode.creation_time = now;
            inode.modification_time = now;
            inode.access_time = now;

            // Store target path (fast symlink if small enough)
            if target.len() <= 60 {
                let bytes = target.as_bytes();
                // Copy bytes individually into the blocks array
                for (i, &byte) in bytes.iter().enumerate() {
                    let block_idx = i / 4;
                    let byte_idx = i % 4;
                    let shift = byte_idx * 8;
                    
                    // For each byte, we need to modify the correct u32 in blocks
                    // preserving the other bytes in that u32
                    let mask = !(0xFF << shift);  // clear the byte we want to write
                    let byte_shifted = (byte as u32) << shift;  // shift our byte into position
                    inode.blocks[block_idx] = (inode.blocks[block_idx] & mask) | byte_shifted;
                }
            } else {
                // Allocate block for target path
                let block = self
                    .allocator
                    .allocate_block()
                    .map_err(|e| FilesystemError::NodeError(e.into()))?;
                inode.blocks[0] = block;
                inode.blocks_count = 1;
            }
        }

        // Create symlink node
        let node = Arc::new(Node::new(
            inode_no,
            inode,
            Arc::clone(&self.block_cache),
            self.superblock.block_size(),
            Arc::clone(&self.allocator),
        ));

        // Add directory entry
        parent
            .add_dir_entry(name, inode_no, FileType::SymbolicLink)
            .map_err(FilesystemError::NodeError)?;

        if target.len() > 60 {
            // Write target path if not using fast symlink
            node.write_at(0, target.as_bytes())
                .map_err(FilesystemError::NodeError)?;
        }

        Ok(node)
    }

    /// Remove a file, directory, or symbolic link
    pub fn remove(&self, path: &str) -> FilesystemResult<()> {
        if !self.mounted.load(Ordering::Acquire) {
            return Err(FilesystemError::NotMounted);
        }

        // Split path into parent directory and name
        let (parent_path, name) = match path.rfind('/') {
            Some(idx) => (&path[..idx], &path[idx + 1..]),
            None => ("/", path),
        };

        // Get parent directory and node to remove
        let parent = self.get_node(parent_path)?;
        let node = self.get_node(path)?;

        if node.is_directory() {
            // Ensure directory is empty (except . and ..)
            let entries = node.read_dir().map_err(FilesystemError::NodeError)?;
            if entries.len() > 2 {
                return Err(FilesystemError::NodeError(NodeError::NotEmpty));
            }
        }

        // Remove directory entry
        parent
            .remove_dir_entry(name)
            .map_err(FilesystemError::NodeError)?;

        // Decrement link count
        node.decrease_link_count().map_err(|e| FilesystemError::NodeError(e))?;

        Ok(())
    }

    /// Write data to a file
    pub fn write_file(&self, path: &str, data: &[u8]) -> FilesystemResult<usize> {
        let node = self.get_node(path)?;
        if !node.is_file() {
            return Err(FilesystemError::NodeError(NodeError::NotFile));
        }

        node.write_at(0, data).map_err(FilesystemError::NodeError)
    }

    /// Read the target of a symbolic link
    pub fn read_link(&self, path: &str) -> FilesystemResult<String> {
        let node = self.get_node(path)?;
        if !node.is_symlink() {
            return Err(FilesystemError::NodeError(NodeError::NotSymlink));
        }

        let mut buffer = vec![0; node.size() as usize];
        node.read_at(0, &mut buffer)
            .map_err(FilesystemError::NodeError)?;

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }
}

/// Filesystem statistics
#[derive(Debug)]
pub struct FilesystemStats {
    pub block_size: u32,
    pub total_blocks: u32,
    pub free_blocks: u32,
    pub total_inodes: u32,
    pub free_inodes: u32,
    pub block_cache_stats: CacheStats,
    pub inode_cache_stats: CacheStats,
}
