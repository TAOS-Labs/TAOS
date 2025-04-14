use crate::{
    constants::{memory::PAGE_SIZE, processes::MAX_FILES},
    events::{current_running_event, futures::sync::Condition, schedule_kernel_on},
    filesys::ext2::structures::FileMode,
    memory::{frame_allocator::alloc_frame, paging::map_kernel_frame, KERNEL_MAPPER},
    processes::process::with_current_pcb,
};
use alloc::{
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, Ordering};
use ext2::{
    filesystem::{Ext2, FilesystemError, FilesystemResult},
    node::{DirEntry, NodeError},
};
use lazy_static::lazy_static;
use spin::{Mutex, Once};
use x86_64::{
    structures::paging::{Page, PageTableFlags, Size4KiB},
    VirtAddr,
};
pub mod ext2;

use async_trait::async_trait;

use bitflags::bitflags;

use crate::{devices::sd_card::SD_CARD, serial_println};

lazy_static! {
    static ref FS_INIT_COMPLETE: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    static ref PAGE_CACHE: Mutex<BTreeMap<usize, Mutex<BTreeMap<usize, Page<Size4KiB>>>>> =
        Mutex::new(BTreeMap::new());
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChmodMode: u16 {
        const UREAD  = 0o400;
        const UWRITE = 0o200;
        const UEXEC  = 0o100;
        const GREAD  = 0o040;
        const GWRITE = 0o020;
        const GEXEC  = 0o010;
        const OREAD  = 0o004;
        const OWRITE = 0o002;
        const OEXEC  = 0o001;
    }
}

#[derive(Debug, Clone)]
pub struct File {
    pathname: String,
    pub fd: usize,
    position: usize,
    flags: OpenFlags,
    pub inode_number: u32,
}

impl File {
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

#[async_trait]
pub trait BlockDevice: Send + Sync {
    async fn read_block(&self, block_num: u64, buf: &mut [u8]) -> FilesystemResult<u8>;
    async fn write_block(&mut self, block_num: u64, buf: &[u8]) -> FilesystemResult<u8>;
    fn block_size(&self) -> usize;
    fn total_blocks(&self) -> u64;
}

/// The main filesystem trait that sits on top of the filesystem
#[async_trait]
pub trait FileSystem {
    async fn create_dir(&mut self, path: &str, chmod_flags: ChmodMode) -> FilesystemResult<()>;
    async fn open_file(&mut self, path: &str, flags: OpenFlags) -> FilesystemResult<usize>;
    async fn remove(&mut self, fd: usize) -> FilesystemResult<()>;
    async fn close_file(&mut self, fd: usize) -> FilesystemResult<()>;
    async fn write_file(&mut self, fd: usize, buf: &[u8]) -> FilesystemResult<usize>;
    async fn seek_file(&mut self, fd: usize, pos: usize) -> FilesystemResult<()>;
    async fn read_file(&mut self, fd: usize, buf: &mut [u8]) -> FilesystemResult<usize>;
    async fn read_dir(&self, path: &str) -> FilesystemResult<Vec<DirEntry>>;
    async fn metadata(&self, fd: usize) -> FilesystemResult<File>;
    async fn add_entry_to_page_cache(&mut self, file: File, offset: usize) -> FilesystemResult<()>;
    async fn page_cache_get_mapping(
        &mut self,
        file: File,
        offset: usize,
    ) -> FilesystemResult<VirtAddr>;
}

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

fn chmod_to_filemode(mode: ChmodMode) -> FileMode {
    let mut out = FileMode::DIR; // directory type must be included

    if mode.contains(ChmodMode::UREAD) {
        out |= FileMode::UREAD;
    }
    if mode.contains(ChmodMode::UWRITE) {
        out |= FileMode::UWRITE;
    }
    if mode.contains(ChmodMode::UEXEC) {
        out |= FileMode::UEXEC;
    }

    if mode.contains(ChmodMode::GREAD) {
        out |= FileMode::GREAD;
    }
    if mode.contains(ChmodMode::GWRITE) {
        out |= FileMode::GWRITE;
    }
    if mode.contains(ChmodMode::GEXEC) {
        out |= FileMode::GEXEC;
    }

    if mode.contains(ChmodMode::OREAD) {
        out |= FileMode::OREAD;
    }
    if mode.contains(ChmodMode::OWRITE) {
        out |= FileMode::OWRITE;
    }
    if mode.contains(ChmodMode::OEXEC) {
        out |= FileMode::OEXEC;
    }

    out
}

pub struct Ext2Wrapper {
    // Outer BTreeMap maps inode # to inner BTreeMap
    // Inner BTreeMap maps file offset (page-aligned) to the kernel virtual address of that associated frame and a dirty bit
    pub page_cache: Mutex<BTreeMap<u32, Arc<Mutex<BTreeMap<usize, (Page<Size4KiB>, bool)>>>>>,

    // Wrapper for Ext2 Filesystem
    filesystem: Mutex<Ext2>,

    // Maps inode # to number of processes
    refcount: Mutex<BTreeMap<usize, usize>>,
}

impl Ext2Wrapper {
    pub fn new(
        page_cache: Mutex<BTreeMap<u32, Arc<Mutex<BTreeMap<usize, (Page<Size4KiB>, bool)>>>>>,
        filesystem: Mutex<Ext2>,
        refcount: Mutex<BTreeMap<usize, usize>>,
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

        let file = with_current_pcb(|pcb| {
            let mut next_fd_guard = pcb.next_fd.lock();
            let fd = *next_fd_guard;
            *next_fd_guard += 1;

            let file = File::new(path.to_string(), fd, 0, flags, inode_number);
            pcb.fd_table[fd] = Some(Arc::new(Mutex::new(file)));

            fd
        });

        Ok(file)
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

        // TODO: Remove entry from Page Cache and write those bits back to the file
        // TODO: Think about the policies for what happens if someone has a file open that is removed - what exactly should happen?
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

        with_current_pcb(|pcb| {
            if pcb.fd_table[fd].is_none() {
                return Err(FilesystemError::InvalidFd);
            }

            pcb.fd_table[fd] = None;
            Ok(())
        })

        // TODO: Think about the logic of when do you write back cached file-backed pages to memory? We need to add some global state that has refcounts for a file
        // being opened and once it's closed by all processes, write back the dirty frames of the page cache
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
        let file = file.lock();
        let bytes_written = self
            .filesystem
            .lock()
            .write_file_at(file.pathname.as_str(), buf, file.position)
            .await?;
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

        while remaining > 0 {
            let page_offset = file_pos & !(PAGE_SIZE - 1);
            let page_offset_in_buf = file_pos % PAGE_SIZE;
            let copy_len = core::cmp::min(PAGE_SIZE - page_offset_in_buf, remaining);
            serial_println!("1");

            // Load the page into cache if not already present
            let virt = match self
                .page_cache_get_mapping(locked_file.clone(), page_offset)
                .await
            {
                Ok(va) => va,
                Err(_) => {
                    serial_println!("2");
                    self.add_entry_to_page_cache(locked_file.clone(), page_offset)
                        .await?;
                    serial_println!("3");
                    let temp = self
                        .page_cache_get_mapping(locked_file.clone(), page_offset)
                        .await?;
                    serial_println!("4");
                    temp
                }
            };

            serial_println!("load the page");

            unsafe {
                let page_ptr = virt.as_ptr::<u8>().add(page_offset_in_buf);
                let dst_ptr = buf.as_mut_ptr().add(total_read);
                core::ptr::copy_nonoverlapping(page_ptr, dst_ptr, copy_len);
            }

            file_pos += copy_len;
            total_read += copy_len;
            remaining -= copy_len;
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
        if !pg_cache.contains_key(&inode_number) {
            pg_cache.insert(inode_number, Arc::new(Mutex::new(BTreeMap::new())));
        }
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
            core::ptr::copy_nonoverlapping(file_buf.as_ptr(), buf_ptr, file_buf.len());
        }

        file_mappings.insert(offset, (Page::containing_address(kernel_va), true));
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
        serial_println!("locked page cache");
        if pg_cache.contains_key(&inode_number) {
            let map = { pg_cache.get(&inode_number).unwrap().lock() };
            serial_println!("locked inner page cache");
            if map.contains_key(&offset) {
                let page = map.get(&offset).unwrap().0;
                return Ok(page.start_address());
            }
        }
        return Err(FilesystemError::CacheError);
    }
}

lazy_static! {
    pub static ref FILESYSTEM: Once<Mutex<Ext2Wrapper>> = Once::new();
}

pub fn init(cpu_id: u32) {
    serial_println!("INITING FS");
    if cpu_id == 0 {
        serial_println!("CPU ID 0");
        schedule_kernel_on(
            0,
            async {
                serial_println!("ABOUT TO FORMAT FS ON INIT");
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

        let meta = user_fs.metadata(fd).await.unwrap();
        assert_eq!(meta.pathname, "./temp/meta.txt");
        assert_eq!(meta.fd, 0);

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
        assert!(!result.is_err());

        user_fs.close_file(fd).await.unwrap();
    }
}
