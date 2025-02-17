//! FAT16 filesystem constants

/// Size of a disk sector in bytes
pub const SECTOR_SIZE: usize = 512;

/// Size of FAT entry in bytes (16-bit)
pub const FAT_ENTRY_SIZE: usize = 2;

/// Maximum number of root directory entries
pub const ROOT_DIR_ENTRIES: usize = 512;

/// Maximum length of filename excluding extension
pub const MAX_FILENAME_LENGTH: usize = 8;

/// Maximum length of file extension
pub const MAX_EXTENSION_LENGTH: usize = 3;

/// File attribute: Read-only
pub const ATTR_READ_ONLY: u8 = 0x01;

/// File attribute: Directory
pub const ATTR_DIRECTORY: u8 = 0x10;

/// File attribute: Archive
pub const ATTR_ARCHIVE: u8 = 0x20;

/// Marker for deleted directory entries
pub const DELETED_ENTRY_MARKER: u8 = 0xE5;
