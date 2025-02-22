use alloc::{boxed::Box, string::String, vec::Vec};
use core::result::Result;

pub mod block;
pub mod ext2;
pub mod fat16;
pub mod vfs;

#[derive(Debug)]
pub enum FsError {
    NotFound,
    AlreadyExists,
    InvalidName,
    IOError,
    NotSupported,
    InvalidOffset,
    NoSpace,
    DirectoryNotEmpty,
}

pub trait BlockDevice: Send + Sync {
    fn read_block(&self, block_num: u64, buf: &mut [u8]) -> Result<(), FsError>;
    fn write_block(&mut self, block_num: u64, buf: &[u8]) -> Result<(), FsError>;
    fn block_size(&self) -> usize;
    fn total_blocks(&self) -> u64;
}

/// Represents a file in the filesystem
pub trait File {
    fn read_with_device(
        &mut self,
        device: &mut dyn BlockDevice,
        buf: &mut [u8],
    ) -> Result<usize, FsError>;
    fn write_with_device(
        &mut self,
        device: &mut dyn BlockDevice,
        buf: &[u8],
    ) -> Result<usize, FsError>;
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, FsError>;
    fn flush(&mut self) -> Result<(), FsError>;
    fn size(&self) -> u64;
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub metadata: FileMetadata,
}

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub size: u64,
    pub is_dir: bool,
    pub created: u64,
    pub modified: u64,
    pub permissions: FilePermissions,
}

#[derive(Debug, Clone)]
pub struct FilePermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

pub enum SeekFrom {
    Start(u64),
    Current(i64),
    End(i64),
}

/// The main filesystem trait that must be implemented by all filesystem types
pub trait FileSystem {
    fn create_file(&mut self, path: &str) -> Result<(), FsError>;
    fn create_dir(&mut self, path: &str) -> Result<(), FsError>;
    fn remove_file(&mut self, path: &str) -> Result<(), FsError>;
    fn remove_dir(&mut self, path: &str) -> Result<(), FsError>;
    fn open_file(&mut self, path: &str) -> Result<usize, FsError>;
    fn close_file(&mut self, fd: usize);
    fn write_file(&mut self, fd: usize, buf: &[u8]) -> Result<usize, FsError>;
    fn seek_file(&mut self, fd: usize, pos: SeekFrom) -> Result<u64, FsError>;
    fn read_file(&mut self, fd: usize, buf: &mut [u8]) -> Result<usize, FsError>;
    fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>, FsError>;
    fn metadata(&self, path: &str) -> Result<FileMetadata, FsError>;
    fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError>;
}
