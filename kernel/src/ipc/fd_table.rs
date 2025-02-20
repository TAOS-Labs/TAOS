use super::error::Error;
use alloc::collections::BTreeMap;
use bitflags::bitflags;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qid {
    pub path: u64,
    pub version: u32,
    pub qtype: QidType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QidType {
    Dir = 0x80,
    Append = 0x40,
    Exclusive = 0x20,
    Mount = 0x10,
    Auth = 0x08,
    TempFile = 0x04,
    File = 0x00,
}

bitflags! {
    #[derive(Clone)]
    pub struct OpenFlags: u32 {
        const READ = 0x01;
        const WRITE = 0x02;
        const RDWR = Self::READ.bits() | Self::WRITE.bits();
        const TRUNC = 0x04;
        const APPEND = 0x08;
        const EXCL = 0x10;
    }
}

pub struct FdTable {
    fds: BTreeMap<usize, FileDesc>,
    next_fd: AtomicUsize,
}

pub struct FileDesc {
    pub mount_id: usize,
    pub fid: u32,
    pub flags: OpenFlags,
    pub offset: AtomicU64,
}

impl Clone for FileDesc {
    fn clone(&self) -> Self {
        Self {
            mount_id: self.mount_id,
            fid: self.fid,
            flags: self.flags.clone(),
            offset: AtomicU64::new(self.offset.load(Ordering::Relaxed)),
        }
    }
}

impl FdTable {
    pub fn new() -> Self {
        Self {
            fds: BTreeMap::new(),
            next_fd: AtomicUsize::new(0),
        }
    }

    pub fn allocate(&mut self, mount_id: usize, fid: u32, flags: OpenFlags) -> usize {
        let fd = self.next_fd.fetch_add(1, Ordering::Relaxed);
        self.fds.insert(
            fd,
            FileDesc {
                mount_id,
                fid,
                flags,
                offset: AtomicU64::new(0),
            },
        );
        fd
    }

    pub fn get(&self, fd: usize) -> Option<&FileDesc> {
        self.fds.get(&fd)
    }

    pub fn get_offset(&self, fd: usize) -> Option<u64> {
        self.fds
            .get(&fd)
            .map(|f| f.offset.load(Ordering::Relaxed))
    }

    pub fn remove(&mut self, fd: usize) -> Option<FileDesc> {
        self.fds.remove(&fd)
    }

    pub fn update_offset(&self, fd: usize, new_offset: u64) -> Result<(), Error> {
        if let Some(file) = self.fds.get(&fd) {
            file.offset.store(new_offset, Ordering::Relaxed);
            Ok(())
        } else {
            Err(Error::BadFileDescriptor)
        }
    }
}