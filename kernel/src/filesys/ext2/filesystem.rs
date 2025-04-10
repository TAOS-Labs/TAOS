use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, RwLock};
use zerocopy::FromBytes;

use super::{
    allocator::Allocator,
    block_io::{BlockError, BlockIO},
    cache::{block::CachedBlock, BlockCache, Cache, CacheStats, InodeCache},
    get_current_time,
    node::{DirEntry, Node, NodeError},
    structures::{BlockGroupDescriptor, FileMode, FileType, Superblock, EXT2_SIGNATURE},
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
    superblock: Arc<RwLock<Superblock>>,
    /// Block group descriptors
    bgdt: Arc<RwLock<Vec<BlockGroupDescriptor>>>,
    /// Block cache
    block_cache: Arc<Mutex<Box<dyn Cache<u32, CachedBlock>>>>,
    /// Inode cache
    inode_cache: Arc<Mutex<InodeCache>>,
    /// Root directory node
    root: Arc<Mutex<Option<Arc<Node>>>>,
    /// Mounted flag
    mounted: AtomicBool,
    /// Allocator
    allocator: Arc<Mutex<Allocator>>,
}

impl Ext2 {
    /// Create a new Ext2 filesystem instance
    ///
    /// # Arguments
    /// * `device` - The block device containing the filesystem
    pub async fn new(device: Arc<dyn BlockIO>) -> FilesystemResult<Arc<Self>> {
        let superblock = Superblock::from_block(Arc::clone(&device)).await?;

        let superblock_lock = Arc::new(RwLock::new(superblock));

        let bgdt_lock = Arc::new(RwLock::new(Vec::new()));

        let block_cache = Arc::new(Mutex::new(
            Box::new(BlockCache::new(Arc::clone(&device), 1024))
                as Box<dyn Cache<u32, CachedBlock>>,
        ));

        let inode_cache = Arc::new(Mutex::new(InodeCache::new(
            Arc::clone(&device),
            Arc::clone(&superblock_lock),
            Arc::clone(&bgdt_lock),
            Arc::clone(&block_cache),
            1024,
        )));

        let allocator = Arc::new(Mutex::new(Allocator::new(
            Arc::clone(&superblock_lock),
            Arc::clone(&bgdt_lock),
            Arc::clone(&block_cache),
        )));

        let fs = Self {
            device,
            superblock: superblock_lock,
            bgdt: bgdt_lock,
            block_cache,
            inode_cache,
            root: Arc::new(Mutex::new(None)),
            mounted: AtomicBool::new(false),
            allocator,
        };

        Ok(Arc::new(fs))
    }

    /// Mount the filesystem, reading superblock and preparing caches
    pub async fn mount(&self) -> FilesystemResult<()> {
        if self.mounted.load(Ordering::Acquire) {
            return Ok(());
        }

        {
            let superblock = self.superblock.read();
            if superblock.signature != EXT2_SIGNATURE {
                return Err(FilesystemError::InvalidSuperblock);
            }
        }

        let (block_groups, superblock_block_size, bgdt_start) = {
            let superblock = self.superblock.read();
            let block_groups = superblock.block_group_count();
            let block_size = superblock.block_size();
            let bgdt_start = if block_size == 1024 { 2 } else { 1 };
            (block_groups, block_size, bgdt_start)
        };

        let mut bgdt = Vec::with_capacity(block_groups as usize);

        let block_size: usize = superblock_block_size.try_into().unwrap();
        let block_group_desc_size = core::mem::size_of::<BlockGroupDescriptor>();
        let descriptors_per_block = block_size / block_group_desc_size;

        let blocks_to_read = (block_groups as usize).div_ceil(descriptors_per_block);

        for block in 0..blocks_to_read {
            let mut buff = vec![0u8; block_size];
            self.device
                .read_block((bgdt_start + block as u32) as u64, &mut buff)
                .await
                .map_err(FilesystemError::DeviceError)?;

            for i in 0..descriptors_per_block {
                let full_idx = block * descriptors_per_block + i;
                if full_idx < block_groups as usize {
                    bgdt.push(
                        *BlockGroupDescriptor::ref_from_prefix(&buff[i * block_group_desc_size..])
                            .unwrap()
                            .0,
                    );
                }
            }
        }

        {
            let mut bgdt_write = self.bgdt.write();
            *bgdt_write = bgdt;
        }

        let new_block_cache: Box<dyn Cache<u32, CachedBlock>> =
            Box::new(BlockCache::new(Arc::clone(&self.device), 1024));

        {
            let mut block_cache_write = self.block_cache.lock();
            *block_cache_write = new_block_cache;
        }

        let new_inode_cache = InodeCache::new(
            Arc::clone(&self.device),
            Arc::clone(&self.superblock),
            Arc::clone(&self.bgdt),
            Arc::clone(&self.block_cache),
            1024,
        );

        {
            let mut inode_cache_write = self.inode_cache.lock();
            *inode_cache_write = new_inode_cache;
        }

        let new_allocator = Allocator::new(
            Arc::clone(&self.superblock),
            Arc::clone(&self.bgdt),
            Arc::clone(&self.block_cache),
        );

        {
            let mut allocator_write = self.allocator.lock();
            *allocator_write = new_allocator;
        }

        let root_inode = {
            let inode_cache = self.inode_cache.lock();
            inode_cache
                .get(2)
                .await
                .map_err(|_| FilesystemError::CacheError)?
        };

        assert!(root_inode.lock().inode().is_directory());

        let root_node = {
            let superblock = self.superblock.read();

            Arc::new(
                Node::new(
                    2,
                    root_inode,
                    Arc::clone(&self.block_cache),
                    superblock.block_size(),
                    Arc::clone(&self.allocator),
                )
                .await,
            )
        };

        {
            let mut root_write = self.root.lock();
            *root_write = Some(root_node);
        }

        self.mounted.store(true, Ordering::Release);
        Ok(())
    }

    /// Unmount the filesystem
    pub async fn unmount(&self) -> FilesystemResult<()> {
        if !self.mounted.load(Ordering::Acquire) {
            return Ok(());
        }

        {
            let inode_cache = self.inode_cache.lock();
            inode_cache
                .clear()
                .await
                .map_err(|_| FilesystemError::CacheError)?;
        }

        {
            let block_cache = self.block_cache.lock();
            block_cache
                .clear()
                .await
                .map_err(|_| FilesystemError::CacheError)?;
        }

        {
            let mut root = self.root.lock();
            *root = None;
        }

        self.mounted.store(false, Ordering::Release);
        Ok(())
    }

    /// Get a node by path
    pub async fn get_node(&self, path: &str) -> FilesystemResult<Arc<Node>> {
        if !self.mounted.load(Ordering::Acquire) {
            return Err(FilesystemError::NotMounted);
        }

        if path.is_empty() {
            return Err(FilesystemError::InvalidPath);
        }

        let root = {
            let root_lock = self.root.lock();
            root_lock
                .as_ref()
                .ok_or(FilesystemError::NotMounted)?
                .clone()
        };

        if path == "/" {
            return Ok(root);
        }

        let mut current = root;
        for component in path.split('/').filter(|s| !s.is_empty()) {
            let entries = current
                .read_dir()
                .await
                .map_err(FilesystemError::NodeError)?;

            let entry = entries
                .iter()
                .find(|e| e.name == component)
                .ok_or(FilesystemError::NotFound)?;

            let inode = {
                let inode_cache = self.inode_cache.lock();
                inode_cache
                    .get(entry.inode_no)
                    .await
                    .map_err(|_| FilesystemError::CacheError)?
            };

            current = {
                let superblock = self.superblock.read();
                Arc::new(
                    Node::new(
                        entry.inode_no,
                        inode,
                        Arc::clone(&self.block_cache),
                        superblock.block_size(),
                        Arc::clone(&self.allocator),
                    )
                    .await,
                )
            };
        }

        Ok(current)
    }

    /// Read all entries in a directory
    pub async fn read_dir(&self, path: &str) -> FilesystemResult<Vec<DirEntry>> {
        let node = self.get_node(path).await?;
        node.read_dir().await.map_err(FilesystemError::NodeError)
    }

    /// Read file contents
    pub async fn read_file(&self, path: &str) -> FilesystemResult<Vec<u8>> {
        let node = self.get_node(path).await?;
        if !node.is_file() {
            return Err(FilesystemError::NodeError(NodeError::NotFile));
        }

        let size = node.size() as usize;
        let mut buffer = vec![0; size];
        node.read_at(0, &mut buffer)
            .await
            .map_err(FilesystemError::NodeError)?;

        Ok(buffer)
    }

    /// Get filesystem statistics
    pub fn stats(&self) -> FilesystemResult<FilesystemStats> {
        if !self.mounted.load(Ordering::Acquire) {
            return Err(FilesystemError::NotMounted);
        }

        let superblock = self.superblock.read();
        let block_cache = self.block_cache.lock();
        let inode_cache = self.inode_cache.lock();

        Ok(FilesystemStats {
            block_size: superblock.block_size(),
            total_blocks: superblock.num_blocks,
            free_blocks: superblock.num_unallocated_blocks,
            total_inodes: superblock.num_inodes,
            free_inodes: superblock.num_unallocated_inodes,
            block_cache_stats: block_cache.stats(),
            inode_cache_stats: inode_cache.stats(),
        })
    }

    /// Create a new file
    pub async fn create_file(&self, path: &str, mode: FileMode) -> FilesystemResult<Arc<Node>> {
        if !self.mounted.load(Ordering::Acquire) {
            return Err(FilesystemError::NotMounted);
        }

        let (parent_path, name) = match path.rfind('/') {
            Some(idx) => (&path[..idx + 1], &path[idx + 1..]),
            None => ("/", path),
        };

        if name.is_empty() || name.len() > 255 {
            return Err(FilesystemError::InvalidPath);
        }

        let parent = self.get_node(parent_path).await?;
        if !parent.is_directory() {
            return Err(FilesystemError::NodeError(NodeError::NotDirectory));
        }

        if self.get_node(path).await.is_ok() {
            return Err(FilesystemError::NodeError(NodeError::AlreadyExists));
        }

        let inode_no = {
            let allocator = self.allocator.lock();
            allocator
                .allocate_inode()
                .await
                .map_err(|e| FilesystemError::NodeError(e.into()))?
        };

        let inode = {
            let inode_cache = self.inode_cache.lock();
            inode_cache
                .get(inode_no)
                .await
                .map_err(|_| FilesystemError::CacheError)?
        };

        {
            let mut inode = inode.lock();
            let inode = inode.inode_mut();
            inode.mode = mode.bits();
            inode.size_low = 0;
            inode.links_count = 1;
            inode.blocks_count = 0;
            inode.flags = 0;
            let now = get_current_time();
            inode.creation_time = now;
            inode.modification_time = now;
            inode.access_time = now;
        }

        parent
            .add_dir_entry(name, inode_no, FileType::RegularFile)
            .await
            .map_err(FilesystemError::NodeError)?;

        let node = {
            let superblock = self.superblock.read();
            Arc::new(
                Node::new(
                    inode_no,
                    inode,
                    Arc::clone(&self.block_cache),
                    superblock.block_size(),
                    Arc::clone(&self.allocator),
                )
                .await,
            )
        };

        Ok(node)
    }

    /// Create a new directory
    pub async fn create_directory(
        &self,
        path: &str,
        mode: FileMode,
    ) -> FilesystemResult<Arc<Node>> {
        if !self.mounted.load(Ordering::Acquire) {
            return Err(FilesystemError::NotMounted);
        }

        let (parent_path, name) = match path.rfind('/') {
            Some(idx) => (&path[..idx + 1], &path[idx + 1..]),
            None => ("/", path),
        };

        if name.is_empty() || name.len() > 255 {
            return Err(FilesystemError::InvalidPath);
        }

        let parent = self.get_node(parent_path).await?;
        if !parent.is_directory() {
            return Err(FilesystemError::NodeError(NodeError::NotDirectory));
        }

        if self.get_node(path).await.is_ok() {
            return Err(FilesystemError::NodeError(NodeError::AlreadyExists));
        }

        let inode_no = {
            let allocator = self.allocator.lock();
            allocator
                .allocate_inode()
                .await
                .map_err(|e| FilesystemError::NodeError(e.into()))?
        };

        let inode = {
            let inode_cache = self.inode_cache.lock();
            inode_cache
                .get(inode_no)
                .await
                .map_err(|_| FilesystemError::CacheError)?
        };

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

        let node = {
            let superblock = self.superblock.read();
            Arc::new(
                Node::new(
                    inode_no,
                    inode,
                    Arc::clone(&self.block_cache),
                    superblock.block_size(),
                    Arc::clone(&self.allocator),
                )
                .await,
            )
        };

        node.add_dir_entry(".", inode_no, FileType::Directory)
            .await
            .map_err(FilesystemError::NodeError)?;

        node.add_dir_entry("..", parent.number(), FileType::Directory)
            .await
            .map_err(FilesystemError::NodeError)?;

        parent
            .add_dir_entry(name, inode_no, FileType::Directory)
            .await
            .map_err(FilesystemError::NodeError)?;

        Ok(node)
    }

    /// Create a symbolic link
    pub async fn create_symlink(&self, path: &str, target: &str) -> FilesystemResult<Arc<Node>> {
        if !self.mounted.load(Ordering::Acquire) {
            return Err(FilesystemError::NotMounted);
        }

        let (parent_path, name) = match path.rfind('/') {
            Some(idx) => (&path[..idx + 1], &path[idx + 1..]),
            None => ("/", path),
        };

        if name.is_empty() || name.len() > 255 {
            return Err(FilesystemError::InvalidPath);
        }

        let parent = self.get_node(parent_path).await?;
        if !parent.is_directory() {
            return Err(FilesystemError::NodeError(NodeError::NotDirectory));
        }

        if self.get_node(path).await.is_ok() {
            return Err(FilesystemError::NodeError(NodeError::AlreadyExists));
        }

        let inode_no = {
            let allocator = self.allocator.lock();
            allocator
                .allocate_inode()
                .await
                .map_err(|e| FilesystemError::NodeError(e.into()))?
        };

        let inode = {
            let inode_cache = self.inode_cache.lock();
            inode_cache
                .get(inode_no)
                .await
                .map_err(|_| FilesystemError::CacheError)?
        };

        let needs_block_allocation = target.len() > 60;
        let allocated_block = if needs_block_allocation {
            let allocator = self.allocator.lock();
            Some(
                allocator
                    .allocate_block()
                    .await
                    .map_err(|e| FilesystemError::NodeError(e.into()))?,
            )
        } else {
            None
        };

        {
            let mut inode = inode.lock();
            let inode = inode.inode_mut();
            inode.mode = FileMode::LINK.bits();
            inode.size_low = target.len() as u32;
            inode.links_count = 1;
            inode.blocks_count = if needs_block_allocation { 1 } else { 0 };
            inode.flags = 0;
            let now = get_current_time();
            inode.creation_time = now;
            inode.modification_time = now;
            inode.access_time = now;

            // Store target path (fast symlink if small enough)
            if !needs_block_allocation {
                let bytes = target.as_bytes();
                for (i, &byte) in bytes.iter().enumerate() {
                    let block_idx = i / 4;
                    let byte_idx = i % 4;
                    let shift = byte_idx * 8;

                    let mask = !(0xFF << shift); // clear the byte we want to write
                    let byte_shifted = (byte as u32) << shift; // shift our byte into position
                    inode.blocks[block_idx] = (inode.blocks[block_idx] & mask) | byte_shifted;
                }
            } else {
                inode.blocks[0] = allocated_block.unwrap();
            }
        }

        let node = {
            let superblock = self.superblock.read();
            Arc::new(
                Node::new(
                    inode_no,
                    inode,
                    Arc::clone(&self.block_cache),
                    superblock.block_size(),
                    Arc::clone(&self.allocator),
                )
                .await,
            )
        };

        parent
            .add_dir_entry(name, inode_no, FileType::SymbolicLink)
            .await
            .map_err(FilesystemError::NodeError)?;

        if needs_block_allocation {
            // Write target path if not using fast symlink
            node.write_at(0, target.as_bytes())
                .await
                .map_err(FilesystemError::NodeError)?;
        }

        Ok(node)
    }

    /// Remove a file, directory, or symbolic link
    pub async fn remove(&self, path: &str) -> FilesystemResult<()> {
        if !self.mounted.load(Ordering::Acquire) {
            return Err(FilesystemError::NotMounted);
        }

        let (parent_path, name) = match path.rfind('/') {
            Some(idx) => (&path[..idx + 1], &path[idx + 1..]),
            None => ("/", path),
        };

        let parent = self.get_node(parent_path).await?;
        let node = self.get_node(path).await?;

        if node.is_directory() {
            let entries = node.read_dir().await.map_err(FilesystemError::NodeError)?;
            if entries.len() > 2 {
                return Err(FilesystemError::NodeError(NodeError::NotEmpty));
            }
        }

        parent
            .remove_dir_entry(name)
            .await
            .map_err(FilesystemError::NodeError)?;

        node.decrease_link_count()
            .await
            .map_err(FilesystemError::NodeError)?;

        Ok(())
    }

    /// Write data to a file
    pub async fn write_file(&self, path: &str, data: &[u8]) -> FilesystemResult<usize> {
        let node = self.get_node(path).await?;
        if !node.is_file() {
            return Err(FilesystemError::NodeError(NodeError::NotFile));
        }

        node.write_at(0, data)
            .await
            .map_err(FilesystemError::NodeError)
    }

    /// Read the target of a symbolic link
    pub async fn read_link(&self, path: &str) -> FilesystemResult<String> {
        let node = self.get_node(path).await?;
        if !node.is_symlink() {
            return Err(FilesystemError::NodeError(NodeError::NotSymlink));
        }

        let mut buffer = vec![0; node.size() as usize];
        node.read_at(0, &mut buffer)
            .await
            .map_err(FilesystemError::NodeError)?;

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }
}

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
