//! The Kernel Heap
//! Contains the initialization for the kernel heap using the Talc allocator

use crate::{
    constants::memory::{HEAP_SIZE, HEAP_START},
    memory::{frame_allocator::FRAME_ALLOCATOR, paging::create_mapping, MAPPER},
    serial_println,
};
use talc::{ClaimOnOom, Span, Talc, Talck};
use x86_64::{
    structures::paging::{mapper::MapToError, Page, Size4KiB},
    VirtAddr,
};

use super::{bitmap_frame_allocator::BitmapFrameAllocator, frame_allocator::GlobalFrameAllocator};

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ClaimOnOom> = Talc::new(unsafe {
    ClaimOnOom::new(Span::new(HEAP_START, HEAP_START.wrapping_add(HEAP_SIZE)))
})
.lock();

/// Initialize the heap and switch to using the bitmap frame_allocator
///
/// # Returns
/// An error, whether the heap was created successfully or not
pub fn init_heap() -> Result<(), MapToError<Size4KiB>> {
    let page_range = {
        let heap_start = VirtAddr::new(HEAP_START as u64);
        let heap_end = heap_start + HEAP_SIZE as u64 - 1u64;
        let heap_start_page = Page::containing_address(heap_start);
        let heap_end_page = Page::containing_address(heap_end);
        Page::range_inclusive(heap_start_page, heap_end_page)
    };

    for page in page_range {
        create_mapping(page, &mut *MAPPER.lock(), None);
    }

    switch_allocator();

    serial_println!("Allocator switched to bitmap allocator");

    Ok(())
}

/// Switches the allocator from the boot into frame allocator to the bitmap frame allocator
fn switch_allocator() {
    let mut alloc = FRAME_ALLOCATOR.lock();
    match *alloc {
        Some(GlobalFrameAllocator::Boot(ref boot_alloc)) => {
            unsafe {
                let bitmap_frame_allocator = BitmapFrameAllocator::init(
                    boot_alloc.memory_map,
                    boot_alloc.allocated_frames(),
                );
                *alloc = Some(GlobalFrameAllocator::Bitmap(bitmap_frame_allocator));

                serial_println!("new frame allocator set");
            };
        }
        _ => panic!("We must be using Boot Frame Allocator at this point"),
    }
}
