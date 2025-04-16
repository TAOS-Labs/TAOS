//!  Buddy Frame allocator
//!
//! - Another allocator kernel switches into once kernel heap is initialized
//! - Maintains "blocks" of physical memory that are contiguous
//! - Blocks are powers of 2 in size
//! - On allocation, gets the smallest free block and attempts to split it
//! - On deallocation, attempts to coalesce blocks
//! - Allows for O(log N) allocation / deallocation

use core::sync::atomic::{AtomicU16, Ordering};

use crate::{constants::memory::PAGE_SIZE, serial_println};
use alloc::{boxed::Box, vec, vec::Vec};
use limine::{memory_map::EntryType, response::MemoryMapResponse};
use x86_64::{
    structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size4KiB},
    PhysAddr,
};

/// Describes a Frame for the allocator
#[derive(Debug)]
pub struct FrameDescriptor {
    /// How many active references of this frame there are
    ref_count: AtomicU16,
    /// How many contiguous frames this block comprises of
    order: AtomicU16,
}

impl FrameDescriptor {
    pub const fn new() -> Self {
        Self {
            ref_count: AtomicU16::new(0),
            order: AtomicU16::new(0),
        }
    }
}

impl Default for FrameDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

/// Supporting metadata for the buddy frame allocator
pub struct BuddyFrameAllocator {
    /// Descriptors for every physical frame
    frames: Box<[FrameDescriptor]>,
    /// List of free lists, where each list corresponds to a specific order
    free_lists: Vec<Vec<usize>>,
    /// The total available physical farmes
    total_frames: usize,
    /// Maximum supported order, log_2(total_frames)
    max_order: usize,
    /// Current number of allocated frames
    allocated_count: usize,
    /// Current number of free frames
    free_count: usize,
}

impl BuddyFrameAllocator {
    /// Creates a new BuddyFrameAllocator
    ///
    /// # Arguments
    /// * `total_frames` - total_frames
    ///
    /// # Returns
    /// returns a new instance of a buddy frame allocator
    pub fn new(total_frames: usize) -> Self {
        let max_order = Self::floor_log2(total_frames);

        let mut frames_vec = Vec::with_capacity(total_frames);

        for _ in 0..total_frames {
            frames_vec.push(FrameDescriptor::new());
        }

        let frames = frames_vec.into_boxed_slice();

        let mut free_lists = vec![Vec::new(); max_order + 1];

        let mut index = 0;
        let mut remaining = total_frames;

        while remaining > 0 {
            let mut order = Self::floor_log2(remaining) as u16;

            while index + (1 << order) > total_frames {
                order -= 1;
            }

            free_lists[order as usize].push(index);
            frames[index].order.store(order, Ordering::Relaxed);

            index += 1 << order;
            remaining -= 1 << order;
        }

        Self {
            frames,
            free_lists,
            total_frames,
            max_order,
            allocated_count: 0,
            free_count: total_frames,
        }
    }

    /// Initializes a buddy frame allocator
    ///
    /// # Arguments
    /// * `memory_map` - a memory map response from limine, used for
    ///   giving only usable memory
    /// * `initial_frames` - the frames allocated by boot frame allocator
    ///
    /// # Returns
    /// Returns an initialized buddy frame allocator
    /// # Safety
    /// This method is unsafe because it directly interfaces with Limine's memory map response
    pub unsafe fn init(
        memory_map: &'static MemoryMapResponse,
        initial_frames: impl Iterator<Item = PhysFrame<Size4KiB>>,
    ) -> Self {
        let initial_frames_vec: Vec<PhysFrame<Size4KiB>> = initial_frames.collect();

        // Determine the top (highest address) among USABLE regions.
        let mut true_end: usize = 0;
        for entry in memory_map.entries().iter() {
            if entry.entry_type == EntryType::USABLE {
                let end_addr = entry.base + entry.length;
                if end_addr as usize > true_end {
                    true_end = end_addr as usize;
                }
            }
        }

        let total_frames = true_end.div_ceil(PAGE_SIZE);
        let mut allocator = BuddyFrameAllocator::new(total_frames);

        // Helper closure: returns true if the given frame index is within a USABLE region.
        let is_frame_usable = |frame_index: usize| -> bool {
            let addr = (frame_index * PAGE_SIZE) as u64;
            for entry in memory_map.entries().iter() {
                if entry.entry_type == EntryType::USABLE {
                    let base = entry.base;
                    let length = entry.length;
                    if addr >= base && addr < base + length {
                        return true;
                    }
                }
            }
            false
        };

        let mut frame_count = 0;

        // Reserve all frames that are not in USABLE regions.
        for i in 0..total_frames {
            if !is_frame_usable(i) {
                allocator.reserve_frame(i);
                frame_count += 1;
            }
        }

        // Reserve all frames allocated early.
        for frame in initial_frames_vec {
            let index = frame.start_address().as_u64() as usize / PAGE_SIZE;
            allocator.reserve_frame(index);
            frame_count += 1;
        }

        allocator.free_count -= frame_count;
        allocator.allocated_count += frame_count;

        allocator
    }

    /// Make sure the buddy allocator does not hand out reserved memory
    /// by isolating those frames and removing it from the list
    ///
    /// # Arguments
    /// * `index` - frame index of frame we want to reserve
    fn reserve_frame(&mut self, index: usize) {
        // Iterate over orders from max_order down to 0
        for order in (0..=self.max_order).rev() {
            if let Some(pos) = self.free_lists[order]
                .iter()
                .position(|&base| index >= base && index < base + (1 << order))
            {
                // Remove the free block from the free list.
                let block_base = self.free_lists[order].remove(pos);
                let mut current_base = block_base;
                let mut current_order = order;
                while current_order > 0 {
                    current_order -= 1;
                    let half = 1 << current_order;
                    if index < current_base + half {
                        // Reserved frame is in the left buddy.
                        // Right buddy becomes free.
                        let buddy = current_base + half;
                        self.free_lists[current_order].push(buddy);
                    } else {
                        // Reserved frame is in the right buddy.
                        // Left buddy becomes free.
                        let buddy = current_base;
                        self.free_lists[current_order].push(buddy);
                        // Adjust current_base to the right buddy.
                        current_base += half;
                    }
                }
                self.frames[current_base]
                    .ref_count
                    .store(1, Ordering::Relaxed);
                return;
            }
        }
        // If not found in any free block, assume it's already reserved.
        self.frames[index].ref_count.store(1, Ordering::Relaxed);
    }

    /// Allocate a block of memory
    ///
    ///
    /// # Arguments
    /// * `order` - The size of the block to allocate
    pub fn allocate_block(&mut self, order: u16) -> Vec<PhysFrame<Size4KiB>> {
        let mut found_order = None;
        for o in order..=self.max_order as u16 {
            if !self.free_lists[o as usize].is_empty() {
                found_order = Some(o as usize);
                break;
            }
        }

        let mut order_mut = found_order.expect("Order not found") as u16;

        let block_index = self.free_lists[order_mut as usize]
            .pop()
            .expect("Expected something to be in order list");

        while order_mut > order {
            order_mut -= 1;

            let buddy = block_index + (1 << order_mut);

            self.frames[buddy].order.store(order_mut, Ordering::Relaxed);
            self.free_lists[order_mut as usize].push(buddy);
        }

        let mut frames = Vec::with_capacity(1 << order);

        for i in block_index..(block_index + (1 << order)) {
            let desc = &self.frames[i];
            desc.ref_count.fetch_add(1, Ordering::Relaxed);
            let addr = i * PAGE_SIZE;
            frames.push(PhysFrame::containing_address(PhysAddr::new(addr as u64)));
        }

        self.allocated_count += 1 << order;
        self.free_count -= 1 << order;

        frames
    }

    /// Deallocate a block of memory
    ///
    ///
    /// # Arguments
    /// * `block` - The physical frames that can be deallocated
    pub fn deallocate_block(&mut self, block: Vec<PhysFrame<Size4KiB>>, order: u16) {
        // given frames vec must be of 1 << order size
        assert_eq!(
            block.len(),
            1 << order,
            "Block length does not match the order"
        );

        let base_index = block[0].start_address().as_u64() as usize / PAGE_SIZE;

        // probably should do some checking here for refcounts
        for i in base_index..(base_index + (1 << order)) {
            self.frames[i].ref_count.fetch_sub(1, Ordering::Relaxed);
        }

        let mut current_index = base_index;
        let mut current_order = order;

        // Coalesce
        while current_order as usize <= self.max_order {
            let buddy_index = self.buddy_index(current_index, current_order as usize);

            if buddy_index >= self.total_frames {
                break;
            }

            let buddy_desc = &self.frames[buddy_index];

            // check if the buddy is free and has the same order, break otherwise
            if buddy_desc.ref_count.load(Ordering::Relaxed) > 0
                || buddy_desc.order.load(Ordering::Relaxed) != current_order
            {
                break;
            }

            // remove the buddy from the free list
            if let Some(pos) = self.free_lists[current_order as usize]
                .iter()
                .position(|&i| i == buddy_index)
            {
                self.free_lists[current_order as usize].remove(pos);
            } else {
                break;
            }

            current_index = core::cmp::min(current_index, buddy_index);
            current_order += 1;
        }

        // Update the descriptor for the merged block.
        self.frames[current_index]
            .order
            .store(current_order, Ordering::Relaxed);

        self.free_lists[current_order as usize].push(current_index);

        self.free_count += 1 << order;
        self.allocated_count -= 1 << order;
    }

    /// Increments the reference count for the given physical frame.
    ///
    /// * `frame`: The frame to increment for
    pub fn inc_ref_count(&self, frame: PhysFrame<Size4KiB>) {
        let index = Self::frame_to_index(frame);
        self.frames[index].ref_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements the reference count for the given physical frame.
    /// Returns the new reference count.
    ///
    /// * `frame`: The frame to decrement for
    pub fn dec_ref_count(&self, frame: PhysFrame<Size4KiB>) -> u16 {
        let index = Self::frame_to_index(frame);
        self.frames[index].ref_count.fetch_sub(1, Ordering::Relaxed) - 1
    }

    /// Returns the refcount for a frame
    ///
    /// * `frame`: The frame to get refcount for
    pub fn get_ref_count(&self, frame: PhysFrame<Size4KiB>) -> u16 {
        let index = Self::frame_to_index(frame);
        self.frames[index].ref_count.load(Ordering::Relaxed)
    }

    /// Returns whether a frame is used or not
    ///
    /// * `frame`: the frame to check
    pub fn is_frame_used(&self, frame: PhysFrame<Size4KiB>) -> bool {
        let index = Self::frame_to_index(frame);
        self.frames[index].ref_count.load(Ordering::Relaxed) == 0
    }

    /// Prints the available free frames
    pub fn print_free_frames(&self) {
        serial_println!("{} free frames", self.free_count);
    }

    /// Helper function as we cannot do log2 yet (requires floating point stuff?)
    ///
    /// # Arguments
    /// * `x` - the value we want to compute the floored log of
    fn floor_log2(x: usize) -> usize {
        (core::mem::size_of::<usize>() * 8) - x.leading_zeros() as usize - 1
    }

    /// Computes the buddy index with an index and order
    ///
    /// * `index`: index to compute with
    /// * `order`: order to compute with
    fn buddy_index(&self, index: usize, order: usize) -> usize {
        index ^ (1 << order)
    }

    /// Translates a frame to its index
    ///
    /// * `frame`: The frame to translate over
    pub fn frame_to_index(frame: PhysFrame<Size4KiB>) -> usize {
        frame.start_address().as_u64() as usize / PAGE_SIZE
    }

    /// Gets the relevant FrameDescriptor for a frame
    ///
    /// * `frame`: the frame to get the descriptor for
    pub fn get_frame_descriptor(&self, frame: PhysFrame<Size4KiB>) -> &FrameDescriptor {
        &self.frames[Self::frame_to_index(frame)]
    }
}

unsafe impl FrameAllocator<Size4KiB> for BuddyFrameAllocator {
    /// Allocates a single frame (Order 0 of Allocator)
    /// If order 0 block does not exist yet, splits a higher
    /// order block
    /// Runs in O(Log N) time
    ///
    /// # Returns
    /// Returns either a PhysFrame or None if not available
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let mut found_order = None;

        // we want order 0, so find the closest to that
        for order in 0..=self.max_order {
            if !self.free_lists[order].is_empty() {
                found_order = Some(order);
                break;
            }
        }

        let mut order = found_order? as u16;

        let block_index = self.free_lists[order as usize]
            .pop()
            .expect("Expected something to be in list");

        // if the block we found is greater than order 0, split
        while order > 0 {
            order -= 1;

            let buddy = block_index + (1 << order);

            self.frames[buddy].order.store(order, Ordering::Relaxed);
            self.free_lists[order as usize].push(buddy);
        }

        self.allocated_count += 1;
        self.free_count -= 1;

        // update frame descriptor
        let desc = &self.frames[block_index];
        desc.ref_count.fetch_add(1, Ordering::Relaxed);
        let addr = block_index * PAGE_SIZE;

        Some(PhysFrame::containing_address(PhysAddr::new(addr as u64)))
    }
}

impl FrameDeallocator<Size4KiB> for BuddyFrameAllocator {
    /// Deallocates a frame and attempts to coalesce
    /// Runs in O(log N) time
    ///
    /// # Arguments
    /// `frame` - The PhysFrame that wants to be deallocated
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let mut index = frame.start_address().as_u64() as usize / PAGE_SIZE;

        let desc = &self.frames[index];

        // no reason to deallocate if there are still references
        if desc.ref_count.fetch_sub(1, Ordering::Relaxed) == 0 {
            return;
        }

        let mut order = 0;

        // if buddy is free and of the same order, merge
        while order < self.max_order {
            let buddy_index = self.buddy_index(index, order);

            if buddy_index >= self.total_frames {
                break;
            }

            let buddy_desc = &self.frames[buddy_index];

            // check if the buddy is free and has the same order, break otherwise
            if buddy_desc.ref_count.load(Ordering::Relaxed) > 0
                || buddy_desc.order.load(Ordering::Relaxed) != order as u16
            {
                break;
            }

            // remove the buddy from the free list
            if let Some(pos) = self.free_lists[order]
                .iter()
                .position(|&i| i == buddy_index)
            {
                self.free_lists[order].remove(pos);
            } else {
                panic!("Frame bookkeeping went wrong");
            }

            index = core::cmp::min(index, buddy_index);
            order += 1;
        }

        self.frames[index]
            .order
            .store(order as u16, Ordering::Relaxed);
        self.free_lists[order].push(index);
        self.free_count += 1;
        self.allocated_count -= 1;
    }
}

#[cfg(test)]
mod tests {
    use crate::memory::frame_allocator::{alloc_frame, dealloc_frame, with_buddy_frame_allocator};

    use super::*;

    #[test_case]
    /// Tests that we can allocate and deallocate a single frame
    async fn test_alloc_dealloc_frame() {
        let frame = alloc_frame().expect("Allocation failed");
        dealloc_frame(frame);
    }

    #[test_case]
    /// Tests that we can allocate and deallocate 100 frames
    async fn test_multiple_alloc_dealloc() {
        let alloc_count_before = with_buddy_frame_allocator(|alloc| alloc.allocated_count);

        let mut frames: Vec<PhysFrame> = Vec::with_capacity(100);
        for _ in 0..100 {
            frames.push(alloc_frame().expect("Failed to allocate"));
        }

        (0..100).for_each(|i| {
            dealloc_frame(frames[i]);
        });

        let alloc_count_after = with_buddy_frame_allocator(|alloc| alloc.allocated_count);

        assert_eq!(alloc_count_before, alloc_count_after);
    }

    #[test_case]
    /// Tests that the count of allocated frames is correct after allocation
    async fn test_alloc_frame_count() {
        let alloc_count_before = with_buddy_frame_allocator(|alloc| alloc.allocated_count);

        let frame = alloc_frame().expect("Frame allocation failed");

        let alloc_count_after = with_buddy_frame_allocator(|alloc| alloc.allocated_count);

        assert_eq!(alloc_count_before, alloc_count_after - 1);

        dealloc_frame(frame);
    }

    #[test_case]
    /// Tests that the count of allocated frames is correct after deallocation
    async fn test_dealloc_frame_count() {
        let frame = alloc_frame().expect("Allocation failed");
        let alloc_count_before = with_buddy_frame_allocator(|alloc| alloc.allocated_count);

        dealloc_frame(frame);

        let alloc_count_after = with_buddy_frame_allocator(|alloc| alloc.allocated_count);

        assert_eq!(alloc_count_before, alloc_count_after + 1);
    }

    #[test_case]
    /// Tests that the refcount count for a frame is correct
    async fn test_ref_count() {
        let frame = alloc_frame().expect("Allocation failed");

        with_buddy_frame_allocator(|alloc| {
            assert_eq!(alloc.get_ref_count(frame), 1);
        });

        dealloc_frame(frame);

        with_buddy_frame_allocator(|alloc| {
            assert_eq!(alloc.get_ref_count(frame), 0);
        });
    }

    #[test_case]
    /// Tests allocating a small block of memory
    async fn test_alloc_block_small() {
        let order = 1; // request 2 blocks of memory
        let (frames, alloc_count_before) = with_buddy_frame_allocator(|alloc| {
            let alloc_count_before = alloc.allocated_count;
            let frames = alloc.allocate_block(order);
            let alloc_count_after = alloc.allocated_count;
            assert_eq!(alloc_count_before + 2, alloc_count_after);

            (frames, alloc_count_before)
        });

        for frame in frames {
            with_buddy_frame_allocator(|alloc| {
                assert_eq!(alloc.get_ref_count(frame), 1);
            });
            dealloc_frame(frame);
        }
        with_buddy_frame_allocator(|alloc| {
            let alloc_count_final = alloc.allocated_count;
            assert_eq!(alloc_count_before, alloc_count_final);
        })
    }

    #[test_case]
    /// Tests allocating a large block of memory
    async fn test_alloc_block_large() {
        let order = 8; // request 256 frames of memory
        let (frames, alloc_count_before) = with_buddy_frame_allocator(|alloc| {
            let alloc_count_before = alloc.allocated_count;
            let frames = alloc.allocate_block(order);
            let alloc_count_after = alloc.allocated_count;
            assert_eq!(alloc_count_before + 256, alloc_count_after);

            (frames, alloc_count_before)
        });

        for frame in frames {
            with_buddy_frame_allocator(|alloc| {
                assert_eq!(alloc.get_ref_count(frame), 1);
            });
            dealloc_frame(frame);
        }
        with_buddy_frame_allocator(|alloc| {
            let alloc_count_final = alloc.allocated_count;
            assert_eq!(alloc_count_before, alloc_count_final);
        })
    }

    #[test_case]
    /// Tests allocating and deallocating block counts
    async fn test_alloc_dealloc_block() {
        let order = 1;
        with_buddy_frame_allocator(|alloc| {
            let alloc_count_before = alloc.allocated_count;
            let frames = alloc.allocate_block(order);
            let alloc_count_after = alloc.allocated_count;
            assert_eq!(alloc_count_before + 2, alloc_count_after);

            alloc.deallocate_block(frames, 1);

            let alloc_count_final = alloc.allocated_count;
            assert_eq!(alloc_count_before, alloc_count_final);
        });
    }

    #[test_case]
    /// Tests allocating and deallocating big block counts
    async fn test_alloc_dealloc_block_large() {
        let order = 8;
        with_buddy_frame_allocator(|alloc| {
            let alloc_count_before = alloc.allocated_count;
            let frames = alloc.allocate_block(order);
            let alloc_count_after = alloc.allocated_count;
            assert_eq!(alloc_count_before + 256, alloc_count_after);

            (0..(1 << order)).for_each(|i| {
                assert_eq!(alloc.get_ref_count(frames[i]), 1);
            });

            alloc.deallocate_block(frames, 8);

            let alloc_count_final = alloc.allocated_count;
            assert_eq!(alloc_count_before, alloc_count_final);
        });
    }
}
