//! Filesystem traits and global state
//! Includes definitions for Filesystem related flags and the filesystem trait
//! The filesystem trait sits on top of a filesystem as an abstraction layer and contains the
//! page cache

use crate::{
    constants::{memory::PAGE_SIZE, processes::MAX_FILES},
    events::{
        current_running_event, futures::sync::{BlockMutex, Condition}, get_runner_time, schedule_kernel_on
    },
    filesys::ext2::structures::FileMode,
    memory::{
        frame_allocator::{alloc_frame, dealloc_frame},
        paging::map_kernel_frame,
        KERNEL_MAPPER,
    },
    processes::process::with_current_pcb,
};
use alloc::{
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    cmp,
    sync::atomic::{AtomicBool, Ordering},
};
use ext2::{
    filesystem::{Ext2, FilesystemError, FilesystemResult},
    node::{DirEntry, NodeError},
};
use lazy_static::lazy_static;
use spin::{Mutex, Once};
use x86_64::{
    structures::paging::{Mapper, Page, PageTableFlags, Size4KiB},
    VirtAddr,
};
pub mod ext2;
pub mod syscalls;

use async_trait::async_trait;

use bitflags::bitflags;

use crate::{devices::sd_card::SD_CARD, serial_println};

lazy_static! {
    /// Whether the filesystem has finished initialization
    pub static ref FS_INIT_COMPLETE: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

    /// Global filesystem instance
    pub static ref FILESYSTEM: Once<BlockMutex<Ext2Wrapper>> = Once::new();
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    /// Flags for creating and opening files
    pub struct OpenFlags: u32 {
        // Access modes (no shift needed)
        const O_RDONLY      = 0;             // 0b00
        const O_WRONLY      = 1 << 0;        // 0b01
        const O_RDWR        = 1 << 1;        // 0b10
        const O_ACCMODE     = 0b11;          // Mask for access mode

        const O_CREAT       = 1 << 6;        // 0x40
        const O_EXCL        = 1 << 7;        // 0x80
        const O_NOCTTY      = 1 << 8;        // 0x100
        const O_TRUNC       = 1 << 9;        // 0x200
        const O_APPEND      = 1 << 11;       // 0x800
        const O_NONBLOCK    = 1 << 12;       // 0x1000
        const O_NDELAY      = Self::O_NONBLOCK.bits();

        const O_DSYNC       = 1 << 13;       // 0x2000
        const O_ASYNC       = 1 << 17;       // 0x20000
        const O_DIRECT      = 1 << 18;       // 0x40000
        const O_LARGEFILE   = 1 << 19;       // 0x80000
        const O_DIRECTORY   = 1 << 20;       // 0x100000
        const O_NOFOLLOW    = 1 << 21;       // 0x200000
        const O_NOATIME     = 1 << 23;       // 0x800000
        const O_CLOEXEC     = 1 << 25;       // 0x2000000
        const O_PATH        = 1 << 27;       // 0x8000000

        const O_SYNC        = (1 << 14) | (1 << 22); // 0x10000 | 0x400000 = 0x4010000
        const O_FSYNC       = Self::O_SYNC.bits();

        // O_TMPFILE = 1 << 29 | O_DIRECTORY
        const O_TMPFILE     = (1 << 29) | Self::O_DIRECTORY.bits();
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    /// Flags for file permissions
    pub struct ChmodMode: u16 {
        const UREAD   = 1 << 8;  // 0x100
        const UWRITE  = 1 << 7;  // 0x080
        const UEXEC   = 1 << 6;  // 0x040

        const GREAD   = 1 << 5;  // 0x020
        const GWRITE  = 1 << 4;  // 0x010
        const GEXEC   = 1 << 3;  // 0x008

        const OREAD   = 1 << 2;  // 0x004
        const OWRITE  = 1 << 1;  // 0x002
        const OEXEC   = 1 << 0;  // 0x001
    }
}

#[derive(Debug, Clone)]
/// A file object in the filesystem trait
pub struct File {
    /// The pathname in the filesystem
    pub pathname: String,
    /// File descriptor
    pub fd: usize,
    /// Position we are seeking from in the file
    position: usize,
    #[allow(unused)]
    /// Flags used to open/create file
    /// TODO: Use these flags in enforcment of file operations
    flags: OpenFlags,
    /// The inode number associated with this file
    pub inode_number: u32,
}

impl File {
    /// Creates a new File
    pub fn new(
        pathname: String,
        fd: usize,
        position: usize,
        flags: OpenFlags,
        inode_number: u32,
    ) -> File {
        File {
            pathname,
            fd,
            position,
            flags,
            inode_number,
        }
    }
}

/// The main filesystem trait that sits on top of the filesystem
#[async_trait]
pub trait FileSystem {
    /// Creates a directory
    ///
    /// * `path`: The path for the directory
    /// * `chmod_flags`: Permissions for the directory
    async fn create_dir(&mut self, path: &str, chmod_flags: ChmodMode) -> FilesystemResult<()>;
    /// Open a file
    ///
    /// * `path`: Filepath to open
    /// * `flags`: Permissions on open
    async fn open_file(&mut self, path: &str, flags: OpenFlags) -> FilesystemResult<usize>;
    /// Delete a file
    ///
    /// * `fd`: File descriptor for the file to delete
    async fn remove(&mut self, fd: usize) -> FilesystemResult<()>;
    /// Close a file
    ///
    /// * `fd`: File descriptor for the file to close
    async fn close_file(&mut self, fd: usize) -> FilesystemResult<()>;
    /// Write to a file
    ///
    /// * `fd`: File descriptor for the file to write to
    /// * `buf`: Contents to write
    async fn write_file(&mut self, fd: usize, buf: &[u8]) -> FilesystemResult<usize>;
    /// Set current file position
    ///
    /// * `fd`: File descriptor for the file to seek
    /// * `pos`: new position to seek to
    async fn seek_file(&mut self, fd: usize, pos: usize) -> FilesystemResult<()>;
    /// Read a file
    ///
    /// * `fd`: File descriptor for the file to read
    /// * `buf`: Buffer to read into
    async fn read_file(&mut self, fd: usize, buf: &mut [u8]) -> FilesystemResult<usize>;
    /// Read a directory
    ///
    /// * `path`: Path for the directory to read
    async fn read_dir(&self, path: &str) -> FilesystemResult<Vec<DirEntry>>;
    /// Returns a File struct
    ///
    /// * `fd`: File descriptor to return associated File struct for
    async fn metadata(&self, fd: usize) -> FilesystemResult<File>;
    /// Adds entry to page cache at offset
    ///
    /// * `file`: File to add entry for
    /// * `offset`: Offset at which to map an entry
    async fn add_entry_to_page_cache(&mut self, file: File, offset: usize) -> FilesystemResult<()>;
    /// Get a Page virtual address from the page cache at an offset
    ///
    /// * `file`: File to get page address for
    /// * `offset`: Offset at which to get an entry
    async fn page_cache_get_mapping(
        &mut self,
        file: File,
        offset: usize,
    ) -> FilesystemResult<VirtAddr>;
}

/// Gets the File from the file descriptor
///
/// * `fd`: The relevant file descriptor to get the File for
pub fn get_file(fd: usize) -> FilesystemResult<Arc<Mutex<File>>> {
    if fd >= MAX_FILES {
        return Err(FilesystemError::InvalidFd);
    }
    let file = with_current_pcb(|pcb| {
        let fd_table = &pcb.fd_table;
        fd_table[fd].clone()
    });

    if file.is_none() {
        return Err(FilesystemError::InvalidFd);
    }
    Ok(file.unwrap())
}

/// Gets the file descriptor from the file path
///
/// * `filepath`: The relevant file path to get the File for
pub fn get_fd(filepath: &str) -> FilesystemResult<usize> {
    with_current_pcb(|pcb| {
        for (fd, file_opt) in pcb.fd_table.iter().enumerate() {
            if let Some(file_arc) = file_opt {
                let file = file_arc.lock();
                if file.pathname == filepath {
                    return Ok(fd);
                }
            }
        }
        Err(FilesystemError::InvalidFd)
    })
}

/// Convert between the ChmodMode and the FileMode
///
/// * `mode`: the ChmodMode to convert
fn chmod_to_filemode(mode: ChmodMode) -> FileMode {
    FileMode::DIR | FileMode::from_bits_truncate(mode.bits())
}

/// Type for the filesystem layer's page cache
type PageCache = Mutex<BTreeMap<u32, Arc<Mutex<BTreeMap<usize, Page<Size4KiB>>>>>>;

pub struct Ext2Wrapper {
    // Outer BTreeMap maps inode # to inner BTreeMap
    // Inner BTreeMap maps file offset (page-aligned) to the kernel virtual address of that associated frame and a dirty bit
    pub page_cache: PageCache,

    // Wrapper for Ext2 Filesystem
    pub filesystem: Mutex<Ext2>,

    // Maps inode number to number of processes
    refcount: Mutex<BTreeMap<u32, usize>>,
}

impl Ext2Wrapper {
    pub fn new(
        page_cache: PageCache,
        filesystem: Mutex<Ext2>,
        refcount: Mutex<BTreeMap<u32, usize>>,
    ) -> Ext2Wrapper {
        Ext2Wrapper {
            page_cache,
            filesystem,
            refcount,
        }
    }
}

#[async_trait]
impl FileSystem for Ext2Wrapper {
    async fn create_dir(&mut self, path: &str, chmod_flags: ChmodMode) -> FilesystemResult<()> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }

        let mode = chmod_to_filemode(chmod_flags);

        self.filesystem.lock().create_directory(path, mode).await?;

        Ok(())
    }

    async fn open_file(&mut self, path: &str, flags: OpenFlags) -> FilesystemResult<usize> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }

        let inode_number = if flags.contains(OpenFlags::O_CREAT) {
            let file_mode = FileMode::REG
                | FileMode::UREAD
                | FileMode::UWRITE
                | FileMode::GREAD
                | FileMode::OREAD;

            self.filesystem
                .lock()
                .create_file(path, file_mode)
                .await?
                .number()
        } else {
            self.filesystem.lock().get_node(path).await?.number()
        };

        let fd = with_current_pcb(|pcb| {
            let mut next_fd_guard = pcb.next_fd.lock();
            let fd = *next_fd_guard;
            *next_fd_guard += 1;

            let file = File::new(path.to_string(), fd, 0, flags, inode_number);
            pcb.fd_table[fd] = Some(Arc::new(Mutex::new(file)));

            fd
        });
        self.refcount
            .lock()
            .entry(inode_number)
            .and_modify(|v| *v += 1)
            .or_insert(1);
        Ok(fd)
    }

    async fn remove(&mut self, fd: usize) -> FilesystemResult<()> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }
        let file = get_file(fd);
        if file.is_err() {
            return Err(FilesystemError::InvalidFd);
        }

        // remove the file from the filesystem
        let file = file.unwrap();
        self.filesystem
            .lock()
            .remove(file.lock().pathname.as_str())
            .await?;

        Ok(())
    }

    async fn close_file(&mut self, fd: usize) -> FilesystemResult<()> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }

        if fd >= MAX_FILES {
            return Err(FilesystemError::InvalidFd);
        }
        let fs = self.filesystem.lock();
        let file = get_file(fd)?;
        let file_guard = file.lock();
        let path = file_guard.pathname.clone();
        let inode_number = fs.get_node(&path).await?.number();

        self.refcount
            .lock()
            .entry(inode_number)
            .and_modify(|v| *v -= 1);

        if let Some(&0) = self.refcount.lock().get(&inode_number) {
            if let Some(inner_arc) = self.page_cache.lock().get(&inode_number) {
                let inner = inner_arc.lock();
                for entry in inner.iter() {
                    let offset = entry.0;
                    let page = entry.1;
                    let start_addr = page.start_address().as_u64();
                    let ptr = start_addr as *const u8;
                    let _buffer: &[u8] = unsafe { core::slice::from_raw_parts(ptr, PAGE_SIZE) };
                    fs.write_file_at(&path, _buffer, *offset).await?;

                    let mapper = KERNEL_MAPPER.lock();
                    let frame = mapper.translate_page(*page).unwrap();
                    dealloc_frame(frame);
                }
            }
        }

        with_current_pcb(|pcb| {
            if pcb.fd_table[fd].is_none() {
                return Err(FilesystemError::InvalidFd);
            }
            pcb.fd_table[fd] = None;
            Ok(())
        })?;
        Ok(())
    }

    async fn write_file(&mut self, fd: usize, buf: &[u8]) -> FilesystemResult<usize> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }

        let file = get_file(fd)?;
        let (locked_file, bytes_written, old_size) = {
            let fs = self.filesystem.lock();

            let locked_file = file.lock();
            let old_size = fs.get_node(locked_file.pathname.as_str()).await?.size();

            let bytes_written = fs
                .write_file_at(locked_file.pathname.as_str(), buf, locked_file.position)
                .await?;
            (locked_file, bytes_written, old_size)
        };

        // Round down the start offset and round up the end offset to page boundaries
        let start_offset = (old_size & !((PAGE_SIZE - 1) as u64)) as usize;
        let end_offset = (locked_file.position + bytes_written + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // Invalidate page cache entries
        let mut offset = start_offset;
        if self
            .page_cache_get_mapping(locked_file.clone(), offset)
            .await
            .is_ok()
        {
            let page_cache_guard = self.page_cache.lock();
            let mut inner_mapping = page_cache_guard
                .get(&locked_file.inode_number)
                .unwrap()
                .lock();
            inner_mapping.remove(&start_offset);
        }

        // Repopulate page cache entries
        offset = start_offset;
        while offset < end_offset {
            self.add_entry_to_page_cache(locked_file.clone(), offset)
                .await?;
            offset += PAGE_SIZE;
        }

        Ok(bytes_written)
    }

    async fn seek_file(&mut self, fd: usize, pos: usize) -> FilesystemResult<()> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }
        let file_lock = get_file(fd)?;
        let mut file = file_lock.lock();
        let fs = self.filesystem.lock();
        let size = fs.get_node(file.pathname.as_str()).await?.size();
        if pos as u64 >= size {
            return Err(FilesystemError::NodeError(NodeError::InvalidOffset));
        }

        file.position = pos;
        Ok(())
    }

    async fn read_file(&mut self, fd: usize, buf: &mut [u8]) -> FilesystemResult<usize> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }

        let file = get_file(fd)?;
        let mut locked_file = { file.lock() };
        let mut remaining = buf.len();
        let mut total_read = 0;
        let mut file_pos = locked_file.position;
        let mut iter = 0;
        while remaining > 0 {
            let start = get_runner_time(0);
            let page_offset = file_pos & !(PAGE_SIZE - 1);
            let page_offset_in_buf = file_pos % PAGE_SIZE;
            let copy_len = core::cmp::min(PAGE_SIZE - page_offset_in_buf, remaining);
            // Load the page into cache if not already present
            let virt = match self
                .page_cache_get_mapping(locked_file.clone(), page_offset)
                .await
            {
                Ok(va) => va,
                Err(_) => {
                    self.add_entry_to_page_cache(locked_file.clone(), page_offset)
                        .await?;
                    let temp = self
                        .page_cache_get_mapping(locked_file.clone(), page_offset)
                        .await?;
                    temp
                }
            };
            unsafe {
                let page_ptr = virt.as_ptr::<u8>().add(page_offset_in_buf);
                let dst_ptr = buf.as_mut_ptr().add(total_read);
                core::ptr::copy_nonoverlapping(page_ptr, dst_ptr, copy_len);
            }

            file_pos += copy_len;
            total_read += copy_len;
            remaining -= copy_len;
            iter += 1;
            let end = get_runner_time(0);

            serial_println!("looping {} times, took {} ticks", iter, end-start);
            // serial_println!("looping {} times", iter);
        }

        locked_file.position = file_pos;
        Ok(total_read)
    }

    async fn read_dir(&self, path: &str) -> FilesystemResult<Vec<DirEntry>> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }
        // let file = get_file(fd)?;
        // let locked_file = file.lock();
        // let path = &locked_file.pathname;
        let entry = self
            .filesystem
            .lock()
            .read_dir(path)
            .await
            .map_err(|_| FilesystemError::InvalidPath)?;
        Ok(entry)
    }

    async fn metadata(&self, fd: usize) -> FilesystemResult<File> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }
        let file = get_file(fd)?;
        let locked_file = file.lock();
        Ok(locked_file.clone())
    }

    async fn add_entry_to_page_cache(&mut self, file: File, offset: usize) -> FilesystemResult<()> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }

        let inode_number = file.inode_number;
        let mut pg_cache = self.page_cache.lock();
        pg_cache
            .entry(inode_number)
            .or_insert_with(|| Arc::new(Mutex::new(BTreeMap::new())));
        let mut file_mappings = pg_cache.get(&inode_number).unwrap().lock();

        // allocate and map frame
        let frame = alloc_frame().ok_or(FilesystemError::CacheError)?;
        let default_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let kernel_va = map_kernel_frame(&mut *KERNEL_MAPPER.lock(), frame, default_flags);
        // clone the pathname before await
        let path = file.pathname.clone();

        // read file buffer
        let file_buf = self.filesystem.lock().read_file_at(&path, offset).await?;

        // Do raw pointer write *after* .await to avoid Send violation
        unsafe {
            let buf_ptr = kernel_va.as_mut_ptr();
            core::ptr::copy_nonoverlapping(
                file_buf.as_ptr(),
                buf_ptr,
                cmp::min(PAGE_SIZE, file_buf.len()),
            );
        }

        file_mappings.insert(offset, Page::containing_address(kernel_va));
        Ok(())
    }

    async fn page_cache_get_mapping(
        &mut self,
        file: File,
        offset: usize,
    ) -> FilesystemResult<VirtAddr> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }
        let inode_number = file.inode_number;
        let pg_cache = self.page_cache.lock();
        if pg_cache.contains_key(&inode_number) {
            let map = { pg_cache.get(&inode_number).unwrap().lock() };
            if map.contains_key(&offset) {
                let page = map.get(&offset).unwrap();
                return Ok(page.start_address());
            }
        }
        return Err(FilesystemError::CacheError);
    }
}

pub fn init(cpu_id: u32) {
    serial_println!("INITING FS");
    if cpu_id == 0 {
        serial_println!("CPU ID 0");
        schedule_kernel_on(
            0,
            async {
                let sd_card = Arc::new(SD_CARD.lock().clone().unwrap());
                let fs = Ext2::new(sd_card).await.unwrap();
                fs.mount().await.unwrap();
                let page_cache = Mutex::new(BTreeMap::new());
                let refcount = Mutex::new(BTreeMap::new());
                let ext2_wrapper = Ext2Wrapper::new(page_cache, Mutex::new(fs), refcount);
                FS_INIT_COMPLETE.store(true, Ordering::Relaxed);
                FILESYSTEM.call_once(|| ext2_wrapper.into());
            },
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    use alloc::{collections::btree_map::BTreeMap, sync::Arc};
    use spin::Mutex;

    use crate::{
        devices::sd_card::SD_CARD,
        filesys::{get_file, ChmodMode, FileSystem, OpenFlags},
        processes::process::with_current_pcb,
    };

    use super::{ext2::filesystem::Ext2, Ext2Wrapper};

    fn active_fd_count() -> usize {
        with_current_pcb(|pcb| pcb.fd_table.iter().filter(|entry| entry.is_some()).count())
    }

    pub async fn setup_fs() -> Ext2Wrapper {
        let sd_card = Arc::new(SD_CARD.lock().clone().unwrap());
        let fs = Ext2::new(sd_card).await.unwrap();
        fs.mount().await.unwrap();

        let page_cache = Mutex::new(BTreeMap::new());
        let refcount = Mutex::new(BTreeMap::new());

        Ext2Wrapper::new(page_cache, Mutex::new(fs), refcount)
    }

    #[test_case]
    pub async fn test_create_and_read_dir() {
        let mut user_fs = setup_fs().await;

        let chmod_mode = ChmodMode::from_bits_truncate(0o755);
        user_fs.create_dir("./temp", chmod_mode).await.unwrap();

        let root_entries = user_fs.read_dir(".").await.unwrap();
        assert!(root_entries.iter().any(|e| e.name == "temp"));

        let sub_entries = user_fs.read_dir("./temp").await.unwrap();
        // . and .. entries
        assert_eq!(sub_entries.len(), 2);
    }

    #[test_case]
    pub async fn test_open_write_read_close() {
        let mut user_fs = setup_fs().await;
        user_fs
            .create_dir("./temp", ChmodMode::from_bits_truncate(0o755))
            .await
            .unwrap();

        let fd = user_fs
            .open_file("./temp/test.txt", OpenFlags::O_WRONLY | OpenFlags::O_CREAT)
            .await
            .unwrap();
        assert!(active_fd_count() > 0);

        user_fs.write_file(fd, b"Test 123").await.unwrap();
        user_fs.seek_file(fd, 0).await.unwrap();

        let mut buf = [0u8; 20];
        let read_bytes = user_fs.read_file(fd, &mut buf).await.unwrap();
        assert_eq!(read_bytes, 20);
        assert_eq!(&buf[..8], b"Test 123");

        user_fs.close_file(fd).await.unwrap();
        assert_eq!(active_fd_count(), 0);
    }

    #[test_case]
    pub async fn test_remove_file() {
        let mut user_fs = setup_fs().await;
        user_fs
            .create_dir("./temp", ChmodMode::from_bits_truncate(0o755))
            .await
            .unwrap();

        let fd = user_fs
            .open_file(
                "./temp/delete_me.txt",
                OpenFlags::O_WRONLY | OpenFlags::O_CREAT,
            )
            .await
            .unwrap();
        user_fs.write_file(fd, b"temp").await.unwrap();
        user_fs.remove(fd).await.unwrap();

        let entries = user_fs.read_dir("./temp").await.unwrap();
        assert!(!entries.iter().any(|e| e.name == "delete_me.txt"));
    }

    #[test_case]
    pub async fn test_seek_file() {
        let mut user_fs = setup_fs().await;
        user_fs
            .create_dir("./temp", ChmodMode::from_bits_truncate(0o755))
            .await
            .unwrap();

        let fd = user_fs
            .open_file("./temp/seek.txt", OpenFlags::O_WRONLY | OpenFlags::O_CREAT)
            .await
            .unwrap();
        user_fs.write_file(fd, b"abcdefghij").await.unwrap();

        user_fs.seek_file(fd, 5).await.unwrap();
        let mut buf = [0u8; 5];
        let read_bytes = user_fs.read_file(fd, &mut buf).await.unwrap();
        assert_eq!(read_bytes, 5);
        assert_eq!(&buf[..5], b"fghij");

        user_fs.close_file(fd).await.unwrap();
    }

    #[test_case]
    pub async fn test_metadata() {
        let mut user_fs = setup_fs().await;
        user_fs
            .create_dir("./temp", ChmodMode::from_bits_truncate(0o755))
            .await
            .unwrap();

        let fd = user_fs
            .open_file("./temp/meta.txt", OpenFlags::O_WRONLY | OpenFlags::O_CREAT)
            .await
            .unwrap();
        user_fs.write_file(fd, b"metadata").await.unwrap();

        {
            let meta = user_fs.metadata(fd).await.unwrap();
            assert_eq!(meta.pathname, "./temp/meta.txt");
            // 0 and 1 are stdin/out
            assert_eq!(meta.fd, 2);
            assert_eq!(meta.flags, OpenFlags::O_WRONLY | OpenFlags::O_CREAT);
        }

        user_fs.close_file(fd).await.unwrap();
    }

    #[test_case]
    pub async fn test_page_cache_entry() {
        let mut user_fs = setup_fs().await;
        user_fs
            .create_dir("./temp", ChmodMode::from_bits_truncate(0o755))
            .await
            .unwrap();

        let fd = user_fs
            .open_file("./temp/cache.txt", OpenFlags::O_WRONLY | OpenFlags::O_CREAT)
            .await
            .unwrap();
        user_fs.write_file(fd, b"pagecache").await.unwrap();
        user_fs.seek_file(fd, 0).await.unwrap();

        let file = get_file(fd).unwrap().lock().clone();
        user_fs
            .add_entry_to_page_cache(file.clone(), 0)
            .await
            .unwrap();

        let result = user_fs.page_cache_get_mapping(file.clone(), 0).await;
        assert!(result.is_ok());

        user_fs.close_file(fd).await.unwrap();
    }
}
