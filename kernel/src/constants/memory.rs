//! Memory management constants defining layout and sizes.

/// Size of a memory page in bytes.
pub const PAGE_SIZE: usize = 4096;

/// Size of a physical memory frame in bytes.
pub const FRAME_SIZE: usize = 4096;

/// Starting virtual address of the kernel heap.
pub const HEAP_START: *mut u8 = 0x_FFFF_8100_0000_0000 as *mut u8;

/// Initial size of the kernel heap (10 MB).
pub const HEAP_SIZE: usize = 1024 * 1024 * 30;

/// Maximum number of frames that can be allocated.
pub const MAX_ALLOCATED_FRAMES: usize = 1024 * 10;

/// Size of each bitmap entry in bits.
pub const BITMAP_ENTRY_SIZE: usize = 64;

/// Value representing a fully allocated bitmap entry.
pub const FULL_BITMAP_ENTRY: u64 = 0xFFFFFFFFFFFFFFFF;

pub const EPHEMERAL_KERNEL_MAPPINGS_START: u64 = 0xFFFF_FF80_0000_0000;
