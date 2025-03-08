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

#[cfg(test)]
mod tests {
    use core::future::Future;

    use alloc::{boxed::Box, string::String, vec, vec::Vec};

    #[test_case]
    fn test_basic_heap_alloc() -> impl Future<Output = ()> + Send + 'static {
        async move {
            let base = Box::new(42);
            assert_eq!(*base, 42);
        }
    }

    #[test_case]
    fn test_vector_alloc() -> impl Future<Output = ()> + Send + 'static {
        async move {
            let mut vec = Vec::new();
            for i in 0..100 {
                vec.push(i);
            }

            assert_eq!(vec.len(), 100);
            let expected_sum: usize = (0..100).sum();
            let sum: usize = vec.iter().sum();

            assert_eq!(sum, expected_sum);
        }
    }

    /// Allocates many boxes in a loop to stress the heap and ensure allocations do not overlap.
    #[test_case]
    fn test_many_allocations() -> impl Future<Output = ()> + Send + 'static {
        async move {
            let mut boxes = Vec::new();
            // Adjust the count based on your heap size
            for i in 0..1000 {
                boxes.push(Box::new(i));
            }
            for (i, b) in boxes.iter().enumerate() {
                assert_eq!(**b, i);
            }
        }
    }

    /// Tests allocation of a String on the heap.
    #[test_case]
    fn test_string_allocation() -> impl Future<Output = ()> + Send + 'static {
        async move {
            let s = String::from("Hello, kernel heap!");
            assert_eq!(s, "Hello, kernel heap!");
        }
    }

    #[test_case]
    fn test_large_allocation() -> impl Future<Output = ()> + Send + 'static {
        async move {
            let size = 1024 * 512;
            let vec: Vec<u8> = vec![1; size];

            assert_eq!(vec.len(), size);

            assert!(vec.iter().all(|&b| b == 1));
        }
    }
}
