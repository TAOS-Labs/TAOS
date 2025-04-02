use crate::{events::schedule_kernel_on, syscalls::syscall_handlers::block_on};
use alloc::{boxed::Box, string::String, vec::Vec, sync::Arc};
use core::{cell::OnceCell, result::Result};
use fat16::Fat16;
use spin::{lock_api::Mutex, Once};
use core::sync::atomic::AtomicBool;
use lazy_static::lazy_static;

pub mod block;
pub mod fat16;
pub mod vfs;

use async_trait::async_trait;

use crate::{devices::sd_card::SD_CARD, serial_println};

lazy_static! {
    static ref FS_INIT_COMPLETE: Arc<AtomicBool> = Arc::new(AtomicBool::new(false)); 
}

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

#[async_trait]
pub trait BlockDevice: Send + Sync {
    async fn read_block(&self, block_num: u64, buf: &mut [u8]) -> Result<(), FsError>;
    async fn write_block(&mut self, block_num: u64, buf: &[u8]) -> Result<(), FsError>;
    fn block_size(&self) -> usize;
    fn total_blocks(&self) -> u64;
}

/// Represents a file in the filesystem
#[async_trait]
pub trait File {
    async fn read_with_device(
        &mut self,
        device: &mut dyn BlockDevice,
        buf: &mut [u8],
    ) -> Result<usize, FsError>;
    async fn write_with_device(
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
#[async_trait]
pub trait FileSystem {
    async fn create_file(&mut self, path: &str) -> Result<(), FsError>;
    async fn create_dir(&mut self, path: &str) -> Result<(), FsError>;
    async fn remove_file(&mut self, path: &str) -> Result<(), FsError>;
    async fn remove_dir(&mut self, path: &str) -> Result<(), FsError>;
    async fn open_file(&mut self, path: &str) -> Result<usize, FsError>;
    fn close_file(&mut self, fd: usize);
    async fn write_file(&mut self, fd: usize, buf: &[u8]) -> Result<usize, FsError>;
    fn seek_file(&mut self, fd: usize, pos: SeekFrom) -> Result<u64, FsError>;
    async fn read_file(&mut self, fd: usize, buf: &mut [u8]) -> Result<usize, FsError>;
    async fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>, FsError>;
    async fn metadata(&self, path: &str) -> Result<FileMetadata, FsError>;
    async fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError>;
}

pub static FILESYSTEM: Once<Mutex<Fat16<'_>>> = Once::new();

pub fn init(cpu_id: u32) {
    if cpu_id == 0 {
        schedule_kernel_on(
            0,
            async {
                    let lock = SD_CARD.lock().clone().unwrap();
                    let device = Box::new(lock);

                    let fs = block_on(async {
                        Fat16::format(device)
                            .await
                            .expect("Could not format Fat16 filesystem")
                    });
                    FILESYSTEM.call_once(|| {
                        FS_INIT_COMPLETE.store(true, core::sync::atomic::Ordering::Relaxed);
                        fs.into()
                    });
                },
            3,
        );
    }
}
