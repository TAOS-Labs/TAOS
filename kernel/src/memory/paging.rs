// This is only there because of get_page_table_entry() function being used in testcases,
// however it could be used in a plethora of places later so I am keeping it for now
#![allow(dead_code)]

use x86_64::{
    structures::paging::{
        Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
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

use super::HHDM_OFFSET;

static mut NEXT_EPH_OFFSET: u64 = 0;

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
pub fn update_mapping(page: Page, mapper: &mut impl Mapper<Size4KiB>, frame: PhysFrame<Size4KiB>) {
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

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

/// Returns a reference to the page table entry for the given page.
/// Needed because x86_64 crate does not expose a method to get PageTableEntry
///
/// # Safety
///
/// The caller must ensure that the provided `mapper` (an OffsetPageTable)
/// was initialized with the correct physical memory offset.
unsafe fn get_page_table_entry<'a>(
    page: Page<Size4KiB>,
    mapper: &OffsetPageTable<'a>,
) -> Option<&'a x86_64::structures::paging::page_table::PageTableEntry> {
    // Calculate indices for the four levels.
    let p4_index = page.p4_index();
    let p3_index = page.p3_index();
    let p2_index = page.p2_index();
    let p1_index = page.p1_index();

    // Get a reference to the level 4 table.
    let level_4_table = mapper.level_4_table();

    // Walk down the page table hierarchy:
    let p4_entry = &level_4_table[p4_index];
    let p3_frame = p4_entry.frame().expect("Entry failed");
    let p3_table_ptr = (*HHDM_OFFSET + p3_frame.start_address().as_u64()).as_ptr::<PageTable>();
    let p3_table = &*p3_table_ptr;

    let p3_entry = &p3_table[p3_index];
    let p2_frame = p3_entry.frame().expect("Entry failed");
    let p2_table_ptr = (*HHDM_OFFSET + p2_frame.start_address().as_u64()).as_ptr::<PageTable>();
    let p2_table = &*p2_table_ptr;

    let p2_entry = &p2_table[p2_index];
    let p1_frame = p2_entry.frame().expect("Entry failed");
    let p1_table_ptr = (*HHDM_OFFSET + p1_frame.start_address().as_u64()).as_ptr::<PageTable>();
    let p1_table = &*p1_table_ptr;

    let pte = &p1_table[p1_index];
    Some(pte)
}

#[cfg(test)]
mod tests {
    use core::{
        future::Future, ptr::{read_volatile, write_volatile}, sync::atomic::{AtomicU64, Ordering}
    };

    use super::*;
    use crate::{constants::memory::PAGE_SIZE, events::schedule_kernel_on, memory::MAPPER};
    use alloc::vec::Vec;
    use x86_64::structures::paging::mapper::TranslateError;

    // used for tlb shootdown testcases
    static PRE_READ: AtomicU64 = AtomicU64::new(0);
    static POST_READ: AtomicU64 = AtomicU64::new(0);

    async fn pre_read(page: Page) {
        let value = unsafe { page.start_address().as_ptr::<u64>().read_volatile() };
        PRE_READ.store(value, Ordering::SeqCst);
    }

    async fn post_read(page: Page) {
        let value = unsafe { page.start_address().as_ptr::<u64>().read_volatile() };
        POST_READ.store(value, Ordering::SeqCst);
    }

    // Test basic remove, as removing and then translating should fail
    #[test_case]
    fn test_remove_mapped_frame() -> impl Future<Output = ()> + Send + 'static {
        async move {
            let mut mapper = MAPPER.lock();
            let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
            let _ = create_mapping(page, &mut *mapper, None);

            remove_mapped_frame(page, &mut *mapper);

            let translate_frame_error = mapper.translate_page(page);

            assert!(matches!(
                translate_frame_error,
                Err(TranslateError::PageNotMapped)
            ));
        }
    }

    // Test basic translation after map returns correct frame
    #[test_case]
    fn test_basic_map_and_translate() -> impl Future<Output = ()> + Send + 'static {
        async move {
            let mut mapper = MAPPER.lock();

            // random test virtual page
            let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
            let frame: PhysFrame = create_mapping(page, &mut *mapper, None);

            let translate_frame = mapper.translate_page(page).expect("Translation failed");

            assert_eq!(frame, translate_frame);

            remove_mapped_frame(page, &mut *mapper);
        }
    }

    // Test that permissions are updated correctly
    #[test_case]
    fn test_update_permissions() -> impl Future<Output = ()> + Send + 'static {
        async move {
            let mut mapper = MAPPER.lock();

            let page: Page = Page::containing_address(VirtAddr::new(0x500000000));
            let _ = create_mapping(page, &mut *mapper, None);

            let flags = PageTableFlags::PRESENT;

            update_permissions(page, &mut *mapper, flags);

            let pte = unsafe { get_page_table_entry(page, &mapper) }.expect("Getting PTE Failed");

            assert!(pte.flags().contains(PageTableFlags::PRESENT));
            assert!(!pte.flags().contains(PageTableFlags::WRITABLE));

            remove_mapped_frame(page, &mut *mapper);
        }
    }

    // Test that contiguous mappings work correctly. Allocates 8 pages in a row.
    #[test_case]
    fn test_contiguous_mapping() -> impl Future<Output = ()> + Send + 'static {
        async move {
            let mut mapper = MAPPER.lock();

            // Define a contiguous region spanning 8 pages.
            let start_page: Page = Page::containing_address(VirtAddr::new(0x500000000));
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
                assert_eq!(val, i as u64,);
            }

            // Cleanup: Unmap all pages.
            for (page, _) in frames {
                remove_mapped_frame(page, &mut *mapper);
            }
        }
    }

    // Goal: Create a mapping and access it on some core such that it is cached.
    // Then, change the mapping to map to a different frame such that a TLB Shootdown
    // is necessary.
    // Finally, check the mapping on another core.
    #[test_case]
    fn test_tlb_shootdowns_cross_core() -> impl Future<Output = ()> + Send + 'static {
        async move {
            const AP: u32 = 1;
            const PRIORITY: usize = 3;
            const PID: u32 = 0;

            // create mapping and set value on current core to cache page
            let page: Page = Page::containing_address(VirtAddr::new(0x500000000));

            {
                let mut mapper = MAPPER.lock();
                let _ = create_mapping(page, &mut *mapper, None);
                unsafe {
                    page.start_address()
                        .as_mut_ptr::<u64>()
                        .write_volatile(0xdead);
                }
            }

            // mapping exists now and is cached for first core

            // tell core 1 to read the value (to TLB cache) and wait until it's done
            schedule_kernel_on(AP, async move { pre_read(page).await }, PRIORITY);

            while PRE_READ.load(Ordering::SeqCst) == 0 {
                core::hint::spin_loop();
            }

            {
                let mut mapper = MAPPER.lock();
                let new_frame = alloc_frame().expect("Could not find a new frame");

                // could say page already mapped, which would be really dumb
                update_mapping(page, &mut *mapper, new_frame);

                unsafe {
                    page.start_address()
                        .as_mut_ptr::<u64>()
                        .write_volatile(0x42);
                }
            }

            // back on core 1, read the value and see if it has changed
            schedule_kernel_on(AP, async move { post_read(page).await }, PRIORITY);

            while POST_READ.load(Ordering::SeqCst) == 0 {
                core::hint::spin_loop();
            }

            assert_eq!(POST_READ.load(Ordering::SeqCst), 0x42);

            let mut mapper = MAPPER.lock();
            remove_mapped_frame(page, &mut *mapper);
        }
    }
}
