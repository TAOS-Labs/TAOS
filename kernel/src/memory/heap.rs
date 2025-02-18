use crate::constants::memory::{HEAP_SIZE, HEAP_START};
use crate::memory::{frame_allocator::FRAME_ALLOCATOR, paging::create_mapping};
use crate::serial_println;
use talc::{ClaimOnOom, Span, Talc, Talck};
use x86_64::{
    structures::paging::{mapper::MapToError, Mapper, Page, Size4KiB},
    VirtAddr,
};

use super::bitmap_frame_allocator::BitmapFrameAllocator;
use super::frame_allocator::GlobalFrameAllocator;

#[global_allocator]
static ALLOCATOR: Talck<spin::Mutex<()>, ClaimOnOom> = Talc::new(unsafe {
    ClaimOnOom::new(Span::new(HEAP_START, HEAP_START.wrapping_add(HEAP_SIZE)))
})
.lock();

/// Initialize the heap and switch to using the bitmap frame_allocator
pub fn init_heap(mapper: &mut impl Mapper<Size4KiB>) -> Result<(), MapToError<Size4KiB>> {
    let page_range = {
        let heap_start = VirtAddr::new(HEAP_START as u64);
        let heap_end = heap_start + HEAP_SIZE as u64 - 1u64;
        let heap_start_page = Page::containing_address(heap_start);
        let heap_end_page = Page::containing_address(heap_end);
        Page::range_inclusive(heap_start_page, heap_end_page)
    };

    for page in page_range {
        create_mapping(page, mapper, None);
    }

    switch_allocator();

    serial_println!("Allocator switched to bitmap allocator");

    Ok(())
}

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
