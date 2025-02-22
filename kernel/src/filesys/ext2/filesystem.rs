use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::{
    block_io::{BlockError, BlockIO},
    cache::{block::CachedBlock, BlockCache, Cache, CacheStats, InodeCache},
    node::{DirEntry, Node, NodeError},
    structures::{BlockGroupDescriptor, Superblock, EXT2_SIGNATURE},
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
    /// Cache error
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
}

impl Ext2 {
    /// Create a new Ext2 filesystem instance
    ///
    /// # Arguments
    /// * `device` - The block device containing the filesystem
    pub fn new(device: Arc<dyn BlockIO>) -> Arc<Self> {
        Arc::new(Self {
            device: Arc::clone(&device),
            superblock: Arc::new(Superblock::default()),
            bgdt: Arc::new([]),
            block_cache: Arc::new(BlockCache::new(Arc::clone(&device), 1024)), // Default sizes
            inode_cache: Arc::new(InodeCache::new(
                Arc::clone(&device),
                Arc::new(Superblock::default()),
                Arc::new([]),
                Arc::new(BlockCache::new(Arc::clone(&device), 1024)),
                1024,
            )),
            root: Arc::new(Mutex::new(None)),
            mounted: AtomicBool::new(false),
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
            Arc::clone(&block_cache),
            superblock.block_size(),
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
