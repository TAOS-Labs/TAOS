use alloc::sync::Arc;
use bitflags::bitflags;
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, KnownLayout};

use super::{
    block_io::BlockIO,
    filesystem::{FilesystemError, FilesystemResult},
};

/// Magic signature for ext2 filesystems
pub const EXT2_SIGNATURE: u16 = 0xEF53;

/// Filesystem state flags
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FilesystemState {
    Clean = 1,
    HasErrors = 2,
}

/// Error handling methods
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ErrorHandler {
    Ignore = 1,
    RemountReadOnly = 2,
    KernelPanic = 3,
}

/// Operating System IDs
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OsId {
    Linux = 0,
    GNU = 1,
    Masix = 2,
    FreeBSD = 3,
    Other = 4,
}

/// Superblock structure - must match disk layout exactly
#[repr(C, packed)]
#[derive(Clone, Debug, Default, FromBytes, KnownLayout, Immutable)]
pub struct Superblock {
    pub num_inodes: u32,
    pub num_blocks: u32,
    pub num_blocks_reserved: u32,
    pub num_unallocated_blocks: u32,
    pub num_unallocated_inodes: u32,
    pub superblock_block: u32,
    pub block_size_shift: u32,
    pub fragment_size_shift: u32,
    pub blocks_per_group: u32,
    pub fragments_per_group: u32,
    pub inodes_per_group: u32,
    pub last_mount_time: u32,
    pub last_write_time: u32,
    pub mounts_since_check: u16,
    pub max_mounts_before_check: u16,
    pub signature: u16,
    pub fs_state: u16,
    pub error_handling: u16,
    pub version_minor: u16,
    pub last_check_time: u32,
    pub check_interval: u32,
    pub os_id: u32,
    pub version_major: u32,
    pub reserved_uid: u16,
    pub reserved_gid: u16,
}

impl Superblock {
    /// Get the block size in bytes
    pub fn block_size(&self) -> u32 {
        1024 << self.block_size_shift
    }

    /// Verify superblock validity
    pub fn is_valid(&self) -> bool {
        self.signature == EXT2_SIGNATURE
            && self.version_major >= 1  // We support version 1+
            && self.block_size() >= 1024
            && self.block_size() <= 4096 // Common size limits
    }

    /// Calculate number of block groups
    pub fn block_group_count(&self) -> u32 {
        let n = self.num_blocks.div_ceil(self.blocks_per_group);
        let n2 = self.num_inodes.div_ceil(self.inodes_per_group);
        assert_eq!(n, n2, "Inconsistent block group counts");
        n
    }

    pub async fn from_block(device: Arc<dyn BlockIO>) -> FilesystemResult<Self> {
        let mut superblock_buff: [u8; 1024] = [0; 1024];
        device
            .read_sector(2, &mut superblock_buff)
            .await
            .map_err(FilesystemError::DeviceError)?;
        device
            .read_sector(3, &mut superblock_buff[512..])
            .await
            .map_err(FilesystemError::DeviceError)?;
        // debug!("Superblock buff = {superblock_buff:?}");
        let superblock_ref = Superblock::ref_from_prefix(&superblock_buff).unwrap().0;
        Result::Ok(superblock_ref.clone())
    }
}

/// Block Group Descriptor - must match disk layout
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, FromBytes, KnownLayout, Immutable)]
pub struct BlockGroupDescriptor {
    pub block_bitmap_block: u32,
    pub inode_bitmap_block: u32,
    pub inode_table_block: u32,
    pub unallocated_blocks: u16,
    pub unallocated_inodes: u16,
    pub directories_count: u16,
    _padding: [u8; 14],
}

impl BlockGroupDescriptor {
    pub fn new(
        block_bitmap_block: u32,
        inode_bitmap_block: u32,
        inode_table_block: u32,
        unallocated_blocks: u16,
        unallocated_inodes: u16,
        directories_count: u16,
    ) -> Self {
        Self {
            block_bitmap_block,
            inode_bitmap_block,
            inode_table_block,
            unallocated_blocks,
            unallocated_inodes,
            directories_count,
            _padding: [0; 14],
        }
    }
}

bitflags! {
    /// File type and permissions
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct FileMode: u16 {
        const SOCK = 0xC000;
        const LINK = 0xA000;
        const REG  = 0x8000;
        const BLK  = 0x6000;
        const DIR  = 0x4000;
        const CHR  = 0x2000;
        const FIFO = 0x1000;

        const SUID = 0x0800;
        const SGID = 0x0400;
        const SVTX = 0x0200;

        const UREAD  = 0x0100;
        const UWRITE = 0x0080;
        const UEXEC  = 0x0040;
        const GREAD  = 0x0020;
        const GWRITE = 0x0010;
        const GEXEC  = 0x0008;
        const OREAD  = 0x0004;
        const OWRITE = 0x0002;
        const OEXEC  = 0x0001;
    }
}

bitflags! {
    /// Inode flags
    #[derive(Debug, Clone, Copy)]
    pub struct InodeFlags: u32 {
        const SECRM   = 0x00000001;
        const UNRM    = 0x00000002;
        const COMPR   = 0x00000004;
        const SYNC    = 0x00000008;
        const IMMUT   = 0x00000010;
        const APPEND  = 0x00000020;
        const NODUMP  = 0x00000040;
        const NOATIME = 0x00000080;
    }
}

/// Inode structure - must match disk layout
#[repr(C, packed)]
#[derive(Debug, Clone, Default)]
pub struct Inode {
    pub mode: u16,
    pub uid: u16,
    pub size_low: u32,
    pub access_time: u32,
    pub creation_time: u32,
    pub modification_time: u32,
    pub deletion_time: u32,
    pub gid: u16,
    pub links_count: u16,
    pub blocks_count: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub blocks: [u32; 15],
    pub generation: u32,
    pub file_acl: u32,
    pub dir_acl: u32,
    pub fragment_addr: u32,
    pub os_specific: [u8; 12],
}

impl Inode {
    /// Get the file type from mode
    pub fn file_type(&self) -> FileMode {
        FileMode::from_bits_truncate(self.mode & 0xF000)
    }

    /// Check if this is a regular file
    pub fn is_file(&self) -> bool {
        self.file_type() == FileMode::REG
    }

    /// Check if this is a directory
    pub fn is_directory(&self) -> bool {
        self.file_type() == FileMode::DIR
    }

    /// Check if this is a symbolic link
    pub fn is_symlink(&self) -> bool {
        self.file_type() == FileMode::LINK
    }

    /// Get full file size (combining high and low 32 bits)
    pub fn size(&self) -> u64 {
        self.size_low as u64
    }
}

/// Directory entry structure - variable length on disk
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
    // name follows as variable length array
}

impl DirectoryEntry {
    /// Size of the fixed portion of directory entry
    pub const fn fixed_size() -> usize {
        size_of::<Self>()
    }

    /// Calculate total size including name
    pub fn total_size(&self) -> usize {
        // Round up to 4-byte alignment
        (DirectoryEntry::fixed_size() + self.name_len as usize + 3) & !3
    }
}

/// File types used in directory entries
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileType {
    Unknown = 0,
    RegularFile = 1,
    Directory = 2,
    CharacterDevice = 3,
    BlockDevice = 4,
    Fifo = 5,
    Socket = 6,
    SymbolicLink = 7,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test_case]
    async fn test_superblock_size() {
        assert_eq!(size_of::<Superblock>(), 84);
    }

    #[test_case]
    async fn test_block_group_descriptor_size() {
        assert_eq!(size_of::<BlockGroupDescriptor>(), 32);
    }

    #[test_case]
    async fn test_inode_size() {
        assert_eq!(size_of::<Inode>(), 128);
    }

    #[test_case]
    async fn test_directory_entry_alignment() {
        let entry = DirectoryEntry {
            inode: 2,
            rec_len: 12,
            name_len: 1,
            file_type: FileType::Directory as u8,
        };
        assert_eq!(entry.total_size() % 4, 0);
    }

    #[test_case]
    async fn test_superblock_validation() {
        let mut sb = Superblock::default();
        assert!(!sb.is_valid()); // Default should be invalid

        sb.signature = EXT2_SIGNATURE;
        sb.version_major = 1;
        sb.block_size_shift = 1; // 2048 byte blocks
        assert!(sb.is_valid());

        sb.block_size_shift = 3; // 8192 byte blocks - too large
        assert!(!sb.is_valid());
    }

    #[test_case]
    async fn test_superblock_block_size() {
        let mut sb = Superblock::default();
        // sb.block_size_shift = 0; // 1024 bytes
        assert_eq!(sb.block_size(), 1024);

        sb.block_size_shift = 1; // 2048 bytes
        assert_eq!(sb.block_size(), 2048);

        sb.block_size_shift = 2; // 4096 bytes
        assert_eq!(sb.block_size(), 4096);
    }

    #[test_case]
    async fn test_block_group_count() {
        let sb = Superblock {
            num_blocks: 1000,
            blocks_per_group: 100,
            num_inodes: 250,
            inodes_per_group: 25,
            ..Default::default()
        };
        assert_eq!(sb.block_group_count(), 10);
    }

    #[test_case]
    async fn test_inode_file_types() {
        let mut inode = Inode {
            mode: FileMode::REG.bits(),
            ..Default::default()
        };
        assert!(inode.is_file());
        assert!(!inode.is_directory());
        assert!(!inode.is_symlink());

        inode.mode = FileMode::DIR.bits();
        assert!(!inode.is_file());
        assert!(inode.is_directory());
        assert!(!inode.is_symlink());

        inode.mode = FileMode::LINK.bits();
        assert!(!inode.is_file());
        assert!(!inode.is_directory());
        assert!(inode.is_symlink());
    }

    #[test_case]
    async fn test_inode_size() {
        let inode = Inode {
            size_low: 1234,
            ..Default::default()
        };
        assert_eq!(inode.size(), 1234);
    }

    #[test_case]
    async fn test_file_mode_permissions() {
        let mode = FileMode::REG | FileMode::UREAD | FileMode::UWRITE;
        assert!(mode.contains(FileMode::REG));
        assert!(mode.contains(FileMode::UREAD));
        assert!(mode.contains(FileMode::UWRITE));
        assert!(!mode.contains(FileMode::UEXEC));
    }

    #[test_case]
    async fn test_directory_entry_sizes() {
        let entry = DirectoryEntry {
            inode: 1,
            rec_len: 16,
            name_len: 5,
            file_type: FileType::RegularFile as u8,
        };

        assert_eq!(DirectoryEntry::fixed_size(), 8); // 4 + 2 + 1 + 1
        assert_eq!(entry.total_size(), 16); // Aligned to 4 bytes
    }
}
