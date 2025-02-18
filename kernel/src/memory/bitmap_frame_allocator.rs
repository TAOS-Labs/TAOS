use crate::{
    constants::memory::{BITMAP_ENTRY_SIZE, FRAME_SIZE, FULL_BITMAP_ENTRY},
    serial_println,
};
use limine::memory_map::EntryType;
use limine::response::MemoryMapResponse;
use x86_64::{
    structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size4KiB},
    PhysAddr,
};

use alloc::{boxed::Box, vec, vec::Vec};

pub struct BitmapFrameAllocator {
    total_frames: usize,
    free_frames: usize,
    to_allocate: usize,
    bitmap: Box<[u64]>,
}

impl BitmapFrameAllocator {
    /// # Safety
    ///
    /// TODO
    pub unsafe fn init(
        memory_map: &'static MemoryMapResponse,
        initial_frames: impl Iterator<Item = PhysFrame>,
    ) -> Self {
        let initial_frames_vec: Vec<PhysFrame> = initial_frames.collect();

        // get the total number of frames (top of usable memory)
        let mut true_end: usize = 0;
        for entry in memory_map.entries().iter() {
            if entry.entry_type == EntryType::USABLE {
                serial_println!("start addr {:#X}, size is {:#X}", entry.base, entry.length);
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
    fn free_region(&mut self, base: usize, length: usize) {
        let start_frame = base / FRAME_SIZE;
        let end_frame = (base + length) / FRAME_SIZE;
        for frame_index in start_frame..end_frame {
            self.clear_bit(frame_index); // set to 0 = free
        }
    }

    /// Check if frame is used. input: PhysFrame, output: bool
    pub fn is_frame_used(&mut self, frame: PhysFrame) -> bool {
        self.is_bit_set(frame.start_address().as_u64() as usize / FRAME_SIZE)
    }

    /// Mark a specific frame as used (1).
    fn mark_frame_used(&mut self, frame: PhysFrame) {
        self.set_bit(frame.start_address().as_u64() as usize / FRAME_SIZE);
    }

    /// Mark a specific frame as free (0).
    fn mark_frame_free(&mut self, frame: PhysFrame) {
        self.clear_bit(frame.start_address().as_u64() as usize / FRAME_SIZE);
    }

    /// set a particular bit (1), taking in frame_index (usize)
    fn set_bit(&mut self, frame_index: usize) {
        assert!(frame_index < self.total_frames);

        let byte_index = frame_index / 64;
        let bit_index = frame_index % 64;

        let mask = 1 << bit_index;
        self.bitmap[byte_index] |= mask;
        self.free_frames -= 1;
    }

    /// clear a particular bit (0), taking in frame_index (usize)
    fn clear_bit(&mut self, frame_index: usize) {
        assert!(frame_index < self.total_frames);

        let byte_index = frame_index / 64;
        let bit_index = frame_index % 64;

        let mask = 1 << bit_index;
        self.bitmap[byte_index] &= !mask;
        self.free_frames += 1;
    }

    /// check if bit is set at frame_index. returns true if bit == 1, false otherwise
    fn is_bit_set(&self, frame_index: usize) -> bool {
        assert!(frame_index < self.total_frames);

        let byte_index = frame_index / 64;
        let bit_index = frame_index % 64;

        let mask = 1 << bit_index;
        (self.bitmap[byte_index] & mask) != 0
    }
}

unsafe impl FrameAllocator<Size4KiB> for BitmapFrameAllocator {
    /// allocates a frame that we can use
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        if self.free_frames == self.total_frames {
            return None;
        }
        loop {
            if !self.is_bit_set(self.to_allocate) {
                self.set_bit(self.to_allocate);
                let addr = self.to_allocate * FRAME_SIZE;
                self.to_allocate = (self.to_allocate + 1) % self.total_frames;
                return Some(PhysFrame::containing_address(PhysAddr::new(addr as u64)));
            }

            self.to_allocate = (self.to_allocate + 1) % self.total_frames;
        }
    }
}

impl FrameDeallocator<Size4KiB> for BitmapFrameAllocator {
    /// deallocates a frame
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        self.mark_frame_free(frame);
    }
}
