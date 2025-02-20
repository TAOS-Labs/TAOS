//! Boot Frame Allocator
//!
//! - Provides a method to allocate memory before a heap is set up
//! - Finds contiguous PhysFrames while avoiding unusable regions of memory

use crate::constants::memory::{FRAME_SIZE, HEAP_SIZE, HEAP_START, MAX_ALLOCATED_FRAMES};
use limine::{
    memory_map::EntryType,
    request::{KernelAddressRequest, MemoryMapRequest},
    response::MemoryMapResponse,
};
use x86_64::{
    structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size4KiB},
    PhysAddr,
};

#[used]
#[link_section = ".requests"]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[used]
#[link_section = ".requests"]
static KERNEL_ADDRESS_REQUEST: KernelAddressRequest = KernelAddressRequest::new();

extern "C" {
    static _kernel_end: u64;
}

/// Boot frame allocator, necessary to set up frame mappings before heap init
///
/// * `memory_map`: Limine memory map response
/// * `next`: the next frame to allocate
/// * `first_frame`: the very first frame allocated
/// * `last_frame`: the very last frame allocated
/// * `allocated_count`: the number of allocated frames
/// * `kernel_start`: where the kernel starts in physical memory, given by Limine
/// * `kernel_end`: where the kernel ends in physical memory, given by Limine
pub struct BootIntoFrameAllocator {
    pub memory_map: &'static MemoryMapResponse,
    next: usize,
    // we note the first and last frame allocated to reallocate later
    first_frame: Option<PhysFrame>,
    last_frame: Option<PhysFrame>,
    allocated_count: usize,
    kernel_start: u64,
    kernel_end: u64,
}

impl BootIntoFrameAllocator {
    /// Init function
    ///
    /// # Returns
    /// Returns a new created boot frame allocator
    ///
    /// # Safety
    /// This function is unsafe as it deals directly with memory map / physmem
    pub unsafe fn init() -> Self {
        let memory_map: &MemoryMapResponse = MEMORY_MAP_REQUEST
            .get_response()
            .expect("Memory map request failed");
        let kernel_address_response = KERNEL_ADDRESS_REQUEST
            .get_response()
            .expect("Kernel Address request failed");

        let kernel_start: u64 = kernel_address_response.physical_base();
        let virtual_kernel_address: u64 = kernel_address_response.virtual_base();
        let kernel_end = unsafe { ((_kernel_end) - virtual_kernel_address) + kernel_start };

        BootIntoFrameAllocator {
            memory_map,
            next: 0,
            first_frame: None,
            last_frame: None,
            allocated_count: 0,
            kernel_start,
            kernel_end,
        }
    }

    /// Function that gives an iterator over sections of usable memory
    ///
    /// # Returns
    /// Returns an iterator of usable PhysFrames
    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> + '_ {
        self.memory_map
            .entries()
            .iter()
            .filter(|r| r.entry_type == EntryType::USABLE)
            .flat_map(|r| (r.base..(r.base + r.length)).step_by(4096))
            .filter(move |&addr| {
                addr < self.kernel_start
                    || addr >= self.kernel_end
                    || addr < HEAP_START as u64
                    || addr > (HEAP_START as u64).wrapping_add(HEAP_SIZE as u64)
            })
            .map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }

    /// Give all frames allocated so far
    ///
    /// # Returns
    /// Returns an iterator over all frames allocated so far
    pub fn allocated_frames(&self) -> impl Iterator<Item = PhysFrame> + '_ {
        let start_addr = self
            .first_frame
            .expect("No frames allocated yet")
            .start_address()
            .as_u64();

        (0..self.allocated_count).map(move |i| {
            let addr = start_addr + (i as u64 * FRAME_SIZE as u64);
            PhysFrame::containing_address(PhysAddr::new(addr))
        })
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootIntoFrameAllocator {
    /// Allocate the single next available frame
    ///
    /// # Returns
    /// Either a PhysFrame or None (if out of frames)
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = Some(self.usable_frames().nth(self.next)?);
        self.next += 1;

        assert!(self.allocated_count < MAX_ALLOCATED_FRAMES);
        if self.first_frame.is_none() {
            self.first_frame = frame;
        }
        self.last_frame = frame;
        self.allocated_count += 1;

        frame
    }
}

impl FrameDeallocator<Size4KiB> for BootIntoFrameAllocator {
    /// FrameDeallocator must be created for generalization,
    /// even though BootIntoFrameAllocator does not support
    /// deallocation
    unsafe fn deallocate_frame(&mut self, _frame: PhysFrame<Size4KiB>) {
        panic!("Cannot deallocate frames for boot frame allocator")
    }
}
