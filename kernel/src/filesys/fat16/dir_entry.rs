//! FAT16 directory entry structure and operations

use super::{constants::*, *};

/// 8.3 format directory entry (32 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DirEntry83 {
    /// 8 character filename
    pub name: [u8; 8],

    /// 3 character extension
    pub ext: [u8; 3],

    /// File attributes (read-only, directory, etc)
    pub attributes: u8,

    /// Reserved
    pub reserved: [u8; 10],

    /// Modification time
    pub time: u16,

    /// Modification date
    pub date: u16,

    /// First cluster number
    pub start_cluster: u16,

    /// File size in bytes
    pub file_size: u32,
}

impl DirEntry83 {
    /// Creates a new file entry with given name and starting cluster
    pub fn new_file(name: &str, ext: &str, start_cluster: u16) -> Self {
        let mut entry = Self {
            name: [0x20; 8],
            ext: [0x20; 3],
            attributes: ATTR_ARCHIVE,
            reserved: [0; 10],
            time: 0,
            date: 0,
            start_cluster,
            file_size: 0,
        };

        let name_bytes = name.as_bytes();
        entry.name[..name_bytes.len().min(8)]
            .copy_from_slice(&name_bytes[..name_bytes.len().min(8)]);

        let ext_bytes = ext.as_bytes();
        entry.ext[..ext_bytes.len().min(3)].copy_from_slice(&ext_bytes[..ext_bytes.len().min(3)]);

        entry
    }

    /// Creates a new directory entry with given name and starting cluster
    pub fn new_directory(name: &str, start_cluster: u16) -> Self {
        let mut entry = Self::new_file(name, "", start_cluster);
        entry.attributes = ATTR_DIRECTORY;
        entry
    }

    /// Returns true if entry is marked as deleted
    pub fn is_deleted(&self) -> bool {
        self.name[0] == DELETED_ENTRY_MARKER
    }

    /// Returns true if entry is empty/unused
    pub fn is_free(&self) -> bool {
        self.name[0] == 0x00
    }

    /// Returns true if entry is a directory
    pub fn is_directory(&self) -> bool {
        self.attributes & ATTR_DIRECTORY != 0
    }

    /// Returns the filename as a string, including extension if present
    pub fn get_name(&self) -> String {
        let name_end = self.name.iter().position(|&x| x == 0x20).unwrap_or(8);
        let ext_end = self.ext.iter().position(|&x| x == 0x20).unwrap_or(3);

        let name = core::str::from_utf8(&self.name[..name_end]).unwrap_or("");
        let ext = core::str::from_utf8(&self.ext[..ext_end]).unwrap_or("");

        if ext_end > 0 {
            alloc::format!("{}.{}", name, ext)
        } else {
            name.into()
        }
    }
}
