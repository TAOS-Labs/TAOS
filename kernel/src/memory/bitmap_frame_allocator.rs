//!  Bitmap frame allocator
//!
//! - Another allocator kernel switches into once kernel heap is initialized
//! - Represents each frame in physical memory as a bit and stores metadata to check against memory leaks
use crate::{
    constants::memory::{BITMAP_ENTRY_SIZE, FRAME_SIZE, FULL_BITMAP_ENTRY},
    serial_println,
};
use limine::{memory_map::EntryType, response::MemoryMapResponse};
use x86_64::{
    structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size4KiB},
    PhysAddr,
};

use alloc::{boxed::Box, vec, vec::Vec};

// Holds bitmapand metadata for allocator
pub struct BitmapFrameAllocator {
    // Total frames usable in physical memory
    total_frames: usize,
    // Total usable frames that are free
    free_frames: usize,
    // Index of next frame to look at for allocation
    to_allocate: usize,
    // Bitmap for representing each frame
    bitmap: Box<[u64]>,
    // Counter for how many total allocations done by allocator
    allocate_count: usize,
    // Counter for total amount of frees done by allocator
    free_count: usize,
}

impl BitmapFrameAllocator {
    /// Initializes bitmap with free and occupied regions in physical memory and updates bitmap metadata.
    ///
    /// # Arguments:
    /// * 'memory_map' - map from Limine telling which parts of physical memory are usable
    /// * 'initial_frames' - iterator of frames from previous allocator to tell which frames are already in use
    ///
    /// # Safety
    /// Unsafe due to requiring to interface directly with memory regions given by the bootloader
    pub unsafe fn init(
        memory_map: &'static MemoryMapResponse,
        initial_frames: impl Iterator<Item = PhysFrame>,
    ) -> Self {
        let initial_frames_vec: Vec<PhysFrame> = initial_frames.collect();

        // get the total number of frames (top of usable memory)
        let mut true_end: usize = 0;
        for entry in memory_map.entries().iter() {
            if entry.entry_type == EntryType::USABLE {
                let end_addr = entry.base + entry.length;
                if end_addr as usize > true_end {
                    true_end = end_addr as usize;
                }
            }
        }
        serial_println!("The top of physmem is: {}", { true_end });
        let total_frames = true_end.div_ceil(FRAME_SIZE);
        let bitmap_size = total_frames.div_ceil(BITMAP_ENTRY_SIZE);
        serial_println!("The bitmap size in bytes is: {}", { bitmap_size });
        let bitmap = vec![FULL_BITMAP_ENTRY; bitmap_size].into_boxed_slice();
        let mut allocator = Self {
            total_frames,
            free_frames: 0,
            to_allocate: initial_frames_vec.len(),
            bitmap,
            allocate_count: 0,
            free_count: 0,
        };

        for entry in memory_map.entries().iter() {
            if entry.entry_type == EntryType::USABLE {
                allocator.free_region(entry.base as usize, entry.length as usize);
                allocator.free_frames += (entry.length as usize).div_ceil(FRAME_SIZE);
            }
        }
        for frame in initial_frames_vec {
            allocator.mark_frame_used(frame);
        }
        allocator
    }

    /// Mark the region [base, base + length) as free in the bitmap.
    ///
    /// # Arguments:
    /// * 'base' - index of which bits should be set to 0
    /// * 'length' - length of range that should be set to 0
    fn free_region(&mut self, base: usize, length: usize) {
        let start_frame = base / FRAME_SIZE;
        let end_frame = (base + length) / FRAME_SIZE;
        for frame_index in start_frame..end_frame {
            self.clear_bit_init(frame_index); // set to 0 = free
        }
    }

    /// Check if frame is used. input: PhysFrame, output: bool
    ///
    /// # Arguments:
    /// * 'PhysFrame' - frame to be checked if in usage
    ///
    /// # Returns:
    /// whether that specific frame is in use or not per bitmap
    pub fn is_frame_used(&mut self, frame: PhysFrame) -> bool {
        self.is_bit_set(frame.start_address().as_u64() as usize / FRAME_SIZE)
    }

    /// Mark a specific frame as used (1).
    ///
    /// # Arguments:
    /// * 'frame' - frame to be marked as used
    fn mark_frame_used(&mut self, frame: PhysFrame) {
        self.set_bit(frame.start_address().as_u64() as usize / FRAME_SIZE);
    }

    /// Mark a specific frame as free (0).
    ///
    /// # Arguments:
    /// * 'frame' - frame to be marked as free
    fn mark_frame_free(&mut self, frame: PhysFrame) {
        self.clear_bit(frame.start_address().as_u64() as usize / FRAME_SIZE);
    }

    /// set a particular bit (1), taking in frame_index (usize)
    ///
    /// # Arguments:
    /// * 'frame_index' - index of bit to be set to 1
    fn set_bit(&mut self, frame_index: usize) {
        assert!(frame_index < self.total_frames);

        let byte_index = frame_index / 64;
        let bit_index = frame_index % 64;

        let mask = 1 << bit_index;
        self.bitmap[byte_index] |= mask;
        self.free_frames -= 1;
    }

    /// clear a particular bit (0), taking in frame_index (usize)
    ///
    /// Asserts that index is within total frames and that bit was originally 1
    ///
    /// # Arguments:
    /// * 'frame_index' - frame that will be cleared in bitmap
    fn clear_bit(&mut self, frame_index: usize) {
        assert!(frame_index < self.total_frames);

        let byte_index = frame_index / 64;
        let bit_index = frame_index % 64;

        let mask = 1 << bit_index;
        if self.bitmap[byte_index] == 0 {
            assert!(
                self.bitmap[byte_index] == 1,
                "Trying to double free a frame!"
            );
        }
        self.bitmap[byte_index] &= !mask;
        self.free_frames += 1;
    }

    /// clear a particular bit (0), taking in frame_index (usize)
    ///
    /// Asserts ONLY that index is within total frames - ONLY use
    /// this in init since you may deal with garbage data so may not
    /// only clear 1's.
    ///
    /// # Arguments:
    /// * 'frame_index' - frame that will be cleared in bitmap
    fn clear_bit_init(&mut self, frame_index: usize) {
        assert!(frame_index < self.total_frames);

        let byte_index = frame_index / 64;
        let bit_index = frame_index % 64;

        let mask = 1 << bit_index;
        self.bitmap[byte_index] &= !mask;
        self.free_frames += 1;
    }

    /// check if bit is set to 1 at frame_index.
    ///
    /// # Arguments:
    /// * 'frame_index' - index to check if it is 1
    ///
    /// # Returns:
    /// True if bit is 1, False if bit is 0
    fn is_bit_set(&self, frame_index: usize) -> bool {
        assert!(frame_index < self.total_frames);

        let byte_index = frame_index / 64;
        let bit_index = frame_index % 64;

        let mask = 1 << bit_index;
        (self.bitmap[byte_index] & mask) != 0
    }

    /// Prints the number of free frames in the bitmap
    pub fn print_bitmap_free_frames(&self) {
        serial_println!("Free frames: {:?}", self.free_frames);
    }

    /// Prints the bitmap itself as an array of u64's
    pub fn print_bitmap(&self) {
        serial_println!("Bitmap: {:?}", self.bitmap);
    }

    /// Prints the total number of allocations
    pub fn get_allocate_count(&self) -> usize {
        self.allocate_count
    }

    /// Prints the total number of frees
    pub fn get_free_count(&self) -> usize {
        self.free_count
    }
}

unsafe impl FrameAllocator<Size4KiB> for BitmapFrameAllocator {
    /// Iterates through the bitmap starting at to_allocate to find first free frame.
    ///
    /// Returns:
    /// None if no frame available, otherwise first available frame
    ///
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        if self.free_frames == self.total_frames {
            return None;
        }
        loop {
            if !self.is_bit_set(self.to_allocate) {
                self.set_bit(self.to_allocate);
                let addr = self.to_allocate * FRAME_SIZE;
                self.to_allocate = (self.to_allocate + 1) % self.total_frames;
                self.allocate_count += 1;
                return Some(PhysFrame::containing_address(PhysAddr::new(addr as u64)));
            }

            self.to_allocate = (self.to_allocate + 1) % self.total_frames;
        }
    }
}

impl FrameDeallocator<Size4KiB> for BitmapFrameAllocator {
    /// deallocates a frame in bitmap
    ///
    /// # Arguments:
    /// * 'frame' - frame to be marked back as free in bitmap
    ///
    /// # Safety
    /// Deallocating memory must be an unsafe operation
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        self.free_count += 1;
        self.mark_frame_free(frame);
    }
}
