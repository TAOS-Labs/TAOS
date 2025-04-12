use x86_64::{
    structures::paging::{
        mapper::{MappedFrame, TranslateResult},
        Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB, Translate,
    },
    VirtAddr,
};

use crate::{
    constants::memory::EPHEMERAL_KERNEL_MAPPINGS_START,
    memory::{
        frame_allocator::{alloc_frame, dealloc_frame, FRAME_ALLOCATOR},
        tlb::tlb_shootdown,
    },
};

use super::{frame_allocator::with_buddy_frame_allocator, HHDM_OFFSET};

static mut NEXT_EPH_OFFSET: u64 = 0;

#[derive(Debug)]
/// Represents errors that can occur during SD card operation or initalization
pub enum PagingError {
    PageNotMappedErr,
}

/// initializes vmem system. activates pml4 and sets up page tables
///
/// # Safety
///
/// This function is unsafe as the caller must guarantee that HHDM_OFFSET is correct
pub unsafe fn init() -> OffsetPageTable<'static> {
    OffsetPageTable::new(active_level_4_table(), *HHDM_OFFSET)
}

/// activates pml4
///
/// # Returns
/// * A pointer to a level 4 page table
///
/// # Safety
///
/// This function is unsafe as the caller must guarantee that HHDM_OFFSET is correct
pub unsafe fn active_level_4_table() -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;

    let (level_4_table_frame, _) = Cr3::read();

    let phys = level_4_table_frame.start_address();
    let virt = *HHDM_OFFSET + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    &mut *page_table_ptr
}

/// Creates a mapping
/// Default flags: PRESENT | WRITABLE
///
/// # Arguments
/// * `page` - a Page that we want to map
/// * `mapper` - anything that implements a the Mapper trait
/// * `flags` - Optional flags, can be None
///
/// # Returns
/// Returns the frame that was allocated and mapped to this page
pub fn create_mapping(
    page: Page,
    mapper: &mut impl Mapper<Size4KiB>,
    flags: Option<PageTableFlags>,
) -> PhysFrame {
    // TODO: Add proper failure handling (ref count increased but page not mapped)
    let frame = alloc_frame().expect("no more frames");

    let _ = unsafe {
        mapper
            .map_to(
                page,
                frame,
                flags.unwrap_or(
                    PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::USER_ACCESSIBLE,
                ),
                FRAME_ALLOCATOR
                    .lock()
                    .as_mut()
                    .expect("Global allocator not initialized"),
            )
            .expect("Mapping failed")
    };

    tlb_shootdown(page.start_address());

    frame
}

/// Creates a mapping to a designated physical frame
/// Default flags: PRESENT | WRITABLE
///
/// # Arguments
/// * `page` - a Page that we want to map
/// * `mapper` - anything that implements a the Mapper trait
/// * `flags` - Optional flags, can be None
///
/// # Returns
/// Returns the frame that was allocated and mapped to this page
pub fn create_mapping_to_frame(
    page: Page,
    mapper: &mut impl Mapper<Size4KiB>,
    flags: Option<PageTableFlags>,
    frame: PhysFrame,
) -> PhysFrame {
    let _ = unsafe {
        mapper
            .map_to(
                page,
                frame,
                flags.unwrap_or(
                    PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::USER_ACCESSIBLE,
                ),
                FRAME_ALLOCATOR
                    .lock()
                    .as_mut()
                    .expect("Global allocator not initialized"),
            )
            .expect("Mapping failed")
    };

    tlb_shootdown(page.start_address());

    frame
}

/// Updates an existing mapping
///
/// Performs a TLB shootdown if the new frame is different than the old
///
/// # Arguments
/// * `page` - a Page that we want to map, must already be mapped
/// * `mapper` - anything that implements a the Mapper trait
/// * `frame` - the PhysFrame<Size4KiB> to map to
pub fn update_mapping(
    page: Page,
    mapper: &mut impl Mapper<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: Option<PageTableFlags>,
) {
    let mut flags = flags.unwrap_or(PageTableFlags::WRITABLE);
    flags.set(PageTableFlags::PRESENT, true);

    let frame_is_used = with_buddy_frame_allocator(|alloc| alloc.get_ref_count(frame) > 0);

    update_permissions(page, mapper, flags);

    let (old_frame, _) = mapper
        .unmap(page)
        .expect("Unmap failed, frame likely was not mapped already");

    if old_frame != frame {
        let _ = unsafe {
            mapper.map_to(
                page,
                frame,
                flags,
                FRAME_ALLOCATOR
                    .lock()
                    .as_mut()
                    .expect("Global allocator not initialized"),
            )
        };

        with_buddy_frame_allocator(|alloc| {
            if alloc.get_ref_count(old_frame) > 0 {
                alloc.dec_ref_count(frame);
            }
            if frame_is_used {
                alloc.inc_ref_count(frame);
            }
        });

        tlb_shootdown(page.start_address());
    }
}

/// Removes an existing mapping
///
/// Performs a TLB Shootdown
///
/// # Arguments
/// * `page` - a Page that we want to map, must already be mapped
/// * `mapper` - anything that implements a the Mapper trait
///
/// # Returns
/// Returns the frame we unmapped
pub fn remove_mapping(page: Page, mapper: &mut impl Mapper<Size4KiB>) -> PhysFrame<Size4KiB> {
    let (frame, _) = mapper.unmap(page).expect("Unmap failed");
    tlb_shootdown(page.start_address());
    frame
}

/// Removes an existing mapping and deallocates the frame
///
/// Performs a TLB Shootdown
///
/// # Arguments
/// * `page` - a Page that we want to map, must already be mapped
/// * `mapper` - anything that implements a the Mapper trait
pub fn remove_mapped_frame(page: Page, mapper: &mut impl Mapper<Size4KiB>) {
    let (frame, _) = mapper.unmap(page).expect("map_to failed");
    dealloc_frame(frame);
    tlb_shootdown(page.start_address());
}

pub fn get_page_flags(
    page: Page,
    mapper: &mut OffsetPageTable,
) -> Result<PageTableFlags, PagingError> {
    let translate_result = mapper.translate(page.start_address());
    match translate_result {
        TranslateResult::Mapped {
            frame,
            offset: _,
            flags,
        } => match frame {
            MappedFrame::Size4KiB(_) => return Result::Ok(flags),
            _ => Result::Err(PagingError::PageNotMappedErr),
        },
        _ => Result::Err(PagingError::PageNotMappedErr),
    }
}

/// Mappes a frame to kernel pages
/// Used for loading
///
/// # Arguments
/// * `mapper` - anything that implements a the Mapper trait
/// * `frame` - A PhysFrame we want to find a kernel mapping for
///
/// # Returns
/// Returns the new virtual address mapped to the inputted frame
///
/// TODO Find a better place for this code
pub fn map_kernel_frame(
    mapper: &mut impl Mapper<Size4KiB>,
    frame: PhysFrame,
    flags: PageTableFlags,
) -> VirtAddr {
    let offset = unsafe {
        let current = NEXT_EPH_OFFSET;
        NEXT_EPH_OFFSET += 0x1000; // move up by a page
        current
    };

    let temp_virt = VirtAddr::new(EPHEMERAL_KERNEL_MAPPINGS_START + offset);
    let temp_page = Page::containing_address(temp_virt);

    unsafe {
        let result = mapper.map_to(
            temp_page,
            frame,
            flags,
            FRAME_ALLOCATOR
                .lock()
                .as_mut()
                .expect("Global allocator not initialized"),
        );
        result.expect("Map To Failed").flush();
    }

    temp_virt
}

/// Update permissions for a specific page
///
/// # Arguments
/// * `page` - Page to update permissions of
/// * `mapper` - Anything that implements a the Mapper trait
/// * `flags` - New permissions
///
/// # Safety
///
/// Updating the flags for a page may result in undefined behavior
pub fn update_permissions(page: Page, mapper: &mut impl Mapper<Size4KiB>, flags: PageTableFlags) {
    let _ = unsafe {
        mapper
            .update_flags(page, flags)
            .expect("Updating flags failed")
    };

    tlb_shootdown(page.start_address());
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::{sync::Arc, vec::Vec};
    use core::{
        ptr::{read_volatile, write_volatile},
        sync::atomic::{AtomicU64, Ordering},
    };
    use x86_64::{
        structures::paging::{mapper::TranslateError, Page, PageTableFlags, PhysFrame},
        VirtAddr,
    };

    // Import functions from the kernel memory module.
    use crate::{
        constants::memory::PAGE_SIZE,
        events::schedule_kernel_on,
        memory::{
            mm::{Mm, VmAreaFlags},
            KERNEL_MAPPER,
        },
        processes::process::{get_current_pid, PROCESS_TABLE},
    };

    // Used for TLB shootdown testcases.
    static PRE_READ: AtomicU64 = AtomicU64::new(0);
    static POST_READ: AtomicU64 = AtomicU64::new(0);

    /// Asynchronously reads a u64 value from the start address of the given page and stores it in PRE_READ.
    async fn pre_read(page: Page) {
        let value = unsafe { page.start_address().as_ptr::<u64>().read_volatile() };
        PRE_READ.store(value, Ordering::SeqCst);
    }

    /// Asynchronously reads a u64 value from the start address of the given page and stores it in POST_READ.
    async fn post_read(page: Page) {
        let value = unsafe { page.start_address().as_ptr::<u64>().read_volatile() };
        POST_READ.store(value, Ordering::SeqCst);
    }

    /// Tests that after a mapping is removed the page translation fails.
    ///
    /// This test creates a mapping for a given virtual page, removes it, and then verifies that
    /// translating the page results in a `PageNotMapped` error.
    #[test_case]
    async fn test_remove_mapped_frame() {
        let mut mapper = KERNEL_MAPPER.lock();
        let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
        let _ = create_mapping(page, &mut *mapper, None);

        remove_mapped_frame(page, &mut *mapper);

        let translate_frame_error = mapper.translate_page(page);

        assert!(matches!(
            translate_frame_error,
            Err(TranslateError::PageNotMapped)
        ));
    }

    /// Tests that mapping a page returns the correct physical frame.
    ///
    /// A mapping is created for a test virtual page and its returned physical frame is then
    /// verified by translating the page. Finally, the mapping is removed.
    #[test_case]
    async fn test_basic_map_and_translate() {
        let mut mapper = KERNEL_MAPPER.lock();

        // Use a test virtual page.
        let page: Page = Page::containing_address(VirtAddr::new(0x400001000));
        let frame: PhysFrame = create_mapping(page, &mut *mapper, None);

        let translate_frame = mapper.translate_page(page).expect("Translation failed");

        assert_eq!(frame, translate_frame);

        remove_mapped_frame(page, &mut *mapper);
    }

    /// Tests that updating page permissions works as expected.
    ///
    /// A mapping is created for a given page and then its permissions are updated (e.g. to make it
    /// read-only by removing the WRITABLE flag). The test then retrieves the page table entry (PTE)
    /// and asserts that it contains the expected flags.
    #[test_case]
    async fn test_update_permissions() {
        let mut mapper = KERNEL_MAPPER.lock();

        let page: Page = Page::containing_address(VirtAddr::new(0x400002000));
        let _ = create_mapping(page, &mut *mapper, None);

        let flags = PageTableFlags::PRESENT; // Only present (read-only).

        update_permissions(page, &mut *mapper, flags);

        let flags = get_page_flags(page, &mut *mapper)
            .ok()
            .expect("Getting page table flags failed");

        assert!(flags.contains(PageTableFlags::PRESENT));
        assert!(!flags.contains(PageTableFlags::WRITABLE));

        remove_mapped_frame(page, &mut *mapper);
    }

    /// Tests that contiguous mappings spanning multiple pages work correctly.
    ///
    /// This test allocates mappings for a contiguous region of 8 pages. Each page is mapped with
    /// writable permissions, a distinct value is written to each page, and then the value is read
    /// back to verify correctness. Finally, all mappings are removed.
    #[test_case] // Uncomment to run this test.
    async fn test_contiguous_mapping() {
        let mut mapper = KERNEL_MAPPER.lock();

        // Define a contiguous region spanning 8 pages.
        let start_page: Page = Page::containing_address(VirtAddr::new(0x400004000));
        let num_pages = 8;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

        let mut frames = Vec::new();
        for i in 0..num_pages {
            let page = Page::from_start_address(start_page.start_address() + i * PAGE_SIZE as u64)
                .expect("Invalid page address");
            let frame = create_mapping(page, &mut *mapper, Some(flags));
            frames.push((page, frame));
        }

        // Write and verify distinct values.
        for (i, (page, _)) in frames.iter().enumerate() {
            let ptr = page.start_address().as_mut_ptr::<u64>();
            unsafe { write_volatile(ptr, i as u64) };
            let val = unsafe { read_volatile(ptr) };
            assert_eq!(val, i as u64);
        }

        // Cleanup: Unmap all pages.
        for (page, _) in frames {
            remove_mapped_frame(page, &mut *mapper);
        }
    }

    /// Tests that TLB shootdowns work correctly across cores.
    ///
    /// This test creates a mapping for a given page and writes a value to cache it on the current core.
    /// It then schedules a read of that page on an alternate core (to load it into that core’s TLB cache).
    /// After that, the mapping is updated to a new frame with new contents and the new value is written.
    /// Finally, the test re-schedules a read on the alternate core and verifies that the new value is observed.
    #[test_case]
    async fn test_tlb_shootdowns_cross_core() {
        const AP: u32 = 1;
        const PRIORITY: usize = 3;

        // Create mapping and set a value on the current core.
        let page: Page = Page::containing_address(VirtAddr::new(0x400010000));

        {
            let mut mapper = KERNEL_MAPPER.lock();
            let _ = create_mapping(page, &mut *mapper, None);
            unsafe {
                page.start_address()
                    .as_mut_ptr::<u64>()
                    .write_volatile(0xdead);
            }
        }

        // Mapping exists now and is cached for the first core.

        // Schedule a read on core 1 to load the page into its TLB cache.
        schedule_kernel_on(AP, async move { pre_read(page).await }, PRIORITY);

        while PRE_READ.load(Ordering::SeqCst) == 0 {
            core::hint::spin_loop();
        }

        {
            let mut mapper = KERNEL_MAPPER.lock();

            let new_frame = alloc_frame().expect("Could not find a new frame");

            // Update the mapping so that a TLB shootdown is necessary.
            update_mapping(
                page,
                &mut *mapper,
                new_frame,
                Some(PageTableFlags::PRESENT | PageTableFlags::WRITABLE),
            );

            unsafe {
                page.start_address()
                    .as_mut_ptr::<u64>()
                    .write_volatile(0x42);
            }
        }

        // Schedule another read on core 1 to verify that the new value is visible.
        schedule_kernel_on(AP, async move { post_read(page).await }, PRIORITY);

        while POST_READ.load(Ordering::SeqCst) == 0 {
            core::hint::spin_loop();
        }

        assert_eq!(POST_READ.load(Ordering::SeqCst), 0x42);

        let mut mapper = KERNEL_MAPPER.lock();
        remove_mapped_frame(page, &mut *mapper);
    }

    // TODO: Update the below tests they won't compile

    // Tests the copy-on-write (COW) mechanism for a mapped page.
    //
    // In a COW scenario, the page is initially mapped as read-only. A write to the page should
    // trigger a fault that results in a new physical frame being allocated and mapped for that page.
    // In this test, we simulate this behavior by:
    // 1. Creating a mapping with read-only permissions.
    // 2. Writing to the page which, triggers a page fault
    // 3. Handling the page fault in our page fault handler
    // 4. Verifying that the new frame is different from the initial one and that the written value is present.
    // #[test_case]
//     async fn test_copy_on_write() {
//         let mut mapper = KERNEL_MAPPER.lock();
//         // Create a dummy PML4 frame.
//         // Locate the current process.
//         let pcb = get_current_pcb();

//         const TEST_VALUE: u64 = 0x42;

//         let page = Page::containing_address(VirtAddr::new(0x400003000));

//         let anon_area = Arc::new(AnonVmArea::new());

//         unsafe {
//             pcb.mm.with_vma_tree_mutable(|tree| {
//                 let _vma1 = Mm::insert_vma(
//                     tree,
//                     page.start_address().as_u64(),
//                     page.start_address().as_u64() + PAGE_SIZE as u64,
//                     anon_area.clone(),
//                     VmAreaFlags::empty(),
//                     true,
//                     0
//                 );
//             });
//         }

//         // Create mapping with read-only permission to simulate a COW mapping.
//         let init_frame = create_mapping(page, &mut *mapper, Some(PageTableFlags::PRESENT));

//         // Write to the page.
//         // Triggers page fault
//         unsafe {
//             page.start_address()
//                 .as_mut_ptr::<u64>()
//                 .write_volatile(TEST_VALUE);
//         }

//         // Now, translating the page should return the new frame.
//         let frame = mapper
//             .translate_page(page)
//             .expect("Translation after COW failed");

//         // The new frame should be different from the original frame.
//         assert_ne!(init_frame, frame);

//         let read_value = unsafe { page.start_address().as_ptr::<u64>().read_volatile() };

//         assert_eq!(read_value, TEST_VALUE);

//         // should not trigger a page fault, we should be able to write now
//         unsafe {
//             page.start_address()
//                 .as_mut_ptr::<u64>()
//                 .write_volatile(0x20);
//         }

//         let new_frame = mapper
//             .translate_page(page)
//             .expect("Translation after COW failed");

//         // We already made this our own, no need to have done COW
//         assert_eq!(frame, new_frame);

//         let read_value2 = unsafe { page.start_address().as_ptr::<u64>().read_volatile() };

//         assert_eq!(read_value2, 0x20);

//         remove_mapped_frame(page, &mut *mapper);
//     }

//     // /// Tests the copy-on-write (COW) mechanism for a mapped page.
//     // ///
//     // /// In a COW scenario, the page is initially mapped as writable, and a full buffer is written
//     // /// Then, the page is marked read only and the first byte in the buffer is written to.
//     // /// This should trigger a page fault that does COW, but it should maintain the rest
//     // /// of the values in the buffer.
//     // #[test_case]
//     async fn test_copy_on_write_full() {
//         let mut mapper = KERNEL_MAPPER.lock();
//         // Create a dummy PML4 frame.
//         // Locate the current process.
//         let pid = get_current_pid();
//         let process = {
//             let process_table = PROCESS_TABLE.read();
//             process_table
//                 .get(&pid)
//                 .expect("can't find pcb in process table")
//                 .clone()
//         };
//         const TEST_VALUE: u8 = 0x2;
//         let page = Page::containing_address(VirtAddr::new(0x400003000));
//         let anon_area = Arc::new(AnonVmArea::new());

//         unsafe {
//             (*process.pcb.get()).mm.with_vma_tree_mutable(|tree| {
//                 let _vma1 = Mm::insert_vma(
//                     tree,
//                     page.start_address().as_u64(),
//                     page.start_address().as_u64() + PAGE_SIZE as u64,
//                     anon_area.clone(),
//                     VmAreaFlags::empty(),
//                     true,
//                     0,
//                 );
//             });
//         }

//         // Create mapping with read-only permission to simulate a COW mapping.
//         let _ = create_mapping(
//             page,
//             &mut *mapper,
//             Some(PageTableFlags::PRESENT | PageTableFlags::WRITABLE),
//         );

//         // Write 1s to the entire buffer
//         unsafe {
//             let buf_ptr = page.start_address().as_mut_ptr::<u8>();
//             core::ptr::write_bytes(buf_ptr, 1, PAGE_SIZE);
//         }

//         // Make it so we page fault on write
//         update_permissions(page, &mut *mapper, PageTableFlags::PRESENT);

//         // Write to the page.
//         // In a real system, this would trigger a page fault to handle copy-on-write.
//         unsafe {
//             page.start_address()
//                 .as_mut_ptr::<u8>()
//                 .write_volatile(TEST_VALUE);
//         }

//         // the cow should not have messed with any data in the buffer besides what
//         // we just wrote to
//         let read_value = unsafe { page.start_address().as_ptr::<u8>().read_volatile() };

//         assert_eq!(read_value, TEST_VALUE);

//         unsafe {
//             let buf_ptr = page.start_address().as_ptr::<u8>();
//             for i in 1..PAGE_SIZE {
//                 let val = *buf_ptr.add(i);
//                 assert_eq!(val, 1, "Byte at offset {} is not 1 (found {})", i, val);
//             }
//         }

//         remove_mapped_frame(page, &mut *mapper);
//     }
}
