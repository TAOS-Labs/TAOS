use crate::{
    constants::processes::MAX_FILES,
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
    async fn create_dir(&mut self, path: &str) -> FilesystemResult<()>;
    async fn open_file(&mut self, path: &str, flags: OpenFlags) -> FilesystemResult<usize>;
    async fn remove(&mut self, fd: usize) -> FilesystemResult<()>;
    async fn close_file(&mut self, fd: usize) -> FilesystemResult<()>;
    async fn write_file(&mut self, fd: usize, buf: &[u8]) -> FilesystemResult<usize>;
    async fn seek_file(&mut self, fd: usize, pos: usize) -> FilesystemResult<()>;
    async fn read_file(&mut self, fd: usize, buf: &mut [u8]) -> FilesystemResult<usize>;
    async fn read_dir(&self, fd: usize) -> FilesystemResult<Vec<DirEntry>>;
    async fn metadata(&self, fd: usize) -> FilesystemResult<File>;
    async fn add_entry_to_page_cache(&mut self, fd: usize, offset: usize) -> FilesystemResult<()>;
    async fn page_cache_get_mapping(
        &mut self,
        fd: usize,
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

    if mode.contains(ChmodMode::UREAD)  { out |= FileMode::UREAD; }
    if mode.contains(ChmodMode::UWRITE) { out |= FileMode::UWRITE; }
    if mode.contains(ChmodMode::UEXEC)  { out |= FileMode::UEXEC; }

    if mode.contains(ChmodMode::GREAD)  { out |= FileMode::GREAD; }
    if mode.contains(ChmodMode::GWRITE) { out |= FileMode::GWRITE; }
    if mode.contains(ChmodMode::GEXEC)  { out |= FileMode::GEXEC; }

    if mode.contains(ChmodMode::OREAD)  { out |= FileMode::OREAD; }
    if mode.contains(ChmodMode::OWRITE) { out |= FileMode::OWRITE; }
    if mode.contains(ChmodMode::OEXEC)  { out |= FileMode::OEXEC; }

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
    async fn create_dir(&mut self, path: &str) -> FilesystemResult<()> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }

        let chmod_mode = ChmodMode::UREAD | ChmodMode::UWRITE | ChmodMode::UEXEC |
                         ChmodMode::GREAD | ChmodMode::GEXEC |
                         ChmodMode::OREAD | ChmodMode::OEXEC; // 0o755

        let mode = chmod_to_filemode(chmod_mode);

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
        self.filesystem.lock().remove(file.lock().pathname.as_str()).await?;

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
        let mut locked_file = file.lock();
        let path = &locked_file.pathname;
        let pos = locked_file.position;
        let file_buf = self.filesystem.lock().read_file_at(path, pos).await;
        if file_buf.is_err() {
            return Err(FilesystemError::InvalidPath);
        }
        let file_buf = file_buf.unwrap();
        buf[..file_buf.len()].copy_from_slice(&(file_buf));
        locked_file.position += file_buf.len();
        Ok(file_buf.len())
    }
    async fn read_dir(&self, fd: usize) -> FilesystemResult<Vec<DirEntry>> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }
        let file = get_file(fd)?;
        let locked_file = file.lock();
        let path = &locked_file.pathname;
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
    async fn add_entry_to_page_cache(&mut self, fd: usize, offset: usize) -> FilesystemResult<()> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }

        let file = get_file(fd)?;
        let file = file.lock();
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
        let file_buf = self
            .filesystem
            .lock()
            .read_file_at(&path, offset)
            .await?;

        // Do raw pointer write *after* .await to avoid Send violation
        unsafe {
            let buf_ptr = kernel_va.as_mut_ptr();
            core::ptr::copy_nonoverlapping(
                file_buf.as_ptr(),
                buf_ptr,
                file_buf.len(),
            );
        }

        file_mappings.insert(offset, (Page::containing_address(kernel_va), true));
        Ok(())
    }

    async fn page_cache_get_mapping(
        &mut self,
        fd: usize,
        offset: usize,
    ) -> FilesystemResult<VirtAddr> {
        if !FS_INIT_COMPLETE.load(Ordering::Relaxed) {
            Condition::new(
                FS_INIT_COMPLETE.clone(),
                current_running_event().expect("Fat16 action outside event"),
            )
            .await;
        }
        let file = get_file(fd)?;
        let locked_file = file.lock();
        let inode_number = locked_file.inode_number;
        let pg_cache = self.page_cache.lock();
        if pg_cache.contains_key(&inode_number) {
            let map = pg_cache.get(&inode_number).unwrap().lock();
            if map.contains_key(&offset) {
                let page = map.get(&offset).unwrap().0;
                return Ok(page.start_address());
            }
        }
        return Err(FilesystemError::CacheError);
    }
}


pub static mut FILESYSTEM: Once<Mutex<Ext2Wrapper>> = Once::new();

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
                unsafe { FILESYSTEM.call_once(|| ext2_wrapper.into()) };
            },
            0,
        );
    }
}
