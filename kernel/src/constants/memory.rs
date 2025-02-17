//! Memory management constants defining layout and sizes.

/// Size of a memory page in bytes.
pub const PAGE_SIZE: usize = 4096;

/// Size of a physical memory frame in bytes.
pub const FRAME_SIZE: usize = 4096;

/// Starting virtual address of the kernel heap.
pub const HEAP_START: *mut u8 = 0x_0000_4444_4444_0000 as *mut u8;

/// Initial size of the kernel heap (1 MB).
pub const HEAP_SIZE: usize = 1024 * 1024;

/// Maximum number of frames that can be allocated.
/// Set to 512 to accommodate heap plus additional allocations.
pub const MAX_ALLOCATED_FRAMES: usize = 512;

/// Size of each bitmap entry in bits.
pub const BITMAP_ENTRY_SIZE: usize = 64;

/// Value representing a fully allocated bitmap entry.
pub const FULL_BITMAP_ENTRY: u64 = 0xFFFFFFFFFFFFFFFF;
