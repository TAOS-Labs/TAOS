//! FAT16 Boot Sector Structure

/// Represents the boot sector of a FAT16 filesystem
#[repr(C, packed)]
pub struct BootSector {
    /// Jump instruction to boot code
    pub jump_boot: [u8; 3],

    /// Name of the system that formatted the volume
    pub oem_name: [u8; 8],

    /// Number of bytes per sector
    pub bytes_per_sector: u16,

    /// Number of sectors per cluster
    pub sectors_per_cluster: u8,

    /// Number of reserved sectors at start of volume
    /// Including the boot sector. Typically 1 for FAT16
    pub reserved_sectors: u16,

    /// Number of FAT copies
    pub fat_count: u8,

    /// Maximum number of root directory entries
    pub root_dir_entries: u16,

    /// Total number of sectors (16-bit)
    /// Used if volume is smaller than 32MB, otherwise use total_sectors_32
    pub total_sectors_16: u16,

    /// Media type descriptor
    pub media_type: u8,

    /// Sectors per FAT
    /// Size of each FAT copy in sectors
    pub sectors_per_fat: u16,

    /// Sectors per track for interrupt 0x13
    pub sectors_per_track: u16,

    /// Number of heads for interrupt 0x13
    pub head_count: u16,

    /// Number of hidden sectors preceding the partition
    /// Used for partition boot sector
    pub hidden_sectors: u32,

    /// Total number of sectors (32-bit)
    /// Used if volume is larger than 32MB
    pub total_sectors_32: u32,

    /// INT 13h drive number
    pub drive_number: u8,

    /// Reserved byte
    pub reserved1: u8,

    /// Extended boot signature
    pub boot_signature: u8,

    /// Volume serial number
    pub volume_id: u32,

    /// Volume label
    pub volume_label: [u8; 11],

    /// Filesystem type string
    pub fs_type: [u8; 8],
}
