use x86_64::{
    structures::paging::{Mapper, OffsetPageTable, Page, PageTable, Size4KiB},
    VirtAddr,
};

use crate::memory::frame_allocator::{alloc_frame, dealloc_frame, FRAME_ALLOCATOR};
use limine::request::HhdmRequest;

#[used]
#[link_section = ".requests"]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

/// initializes vmem system. activates pml4 and sets up page tables
///
/// # Safety
///
/// TODO
pub unsafe fn init() -> OffsetPageTable<'static> {
    let hhdm_response = HHDM_REQUEST.get_response().expect("HHDM request failed");

    let hhdm_base: VirtAddr = VirtAddr::new(hhdm_response.offset());

    let pml4 = active_level_4_table(hhdm_base);

    OffsetPageTable::new(pml4, hhdm_base)
}

/// activates pml4
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;

    let (level_4_table_frame, _) = Cr3::read();

    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    &mut *page_table_ptr
}

/// Creates an example mapping, in unsafe
pub fn create_mapping(page: Page, mapper: &mut impl Mapper<Size4KiB>) {
    use x86_64::structures::paging::PageTableFlags as Flags;

    let flags = Flags::PRESENT | Flags::WRITABLE;
    let frame = alloc_frame().expect("no more frames");

    let map_to_result = unsafe {
        // FIXME: this is not safe, we do it only for testing
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
    map_to_result.expect("map_to failed").flush();
}

pub fn remove_mapping(page: Page, mapper: &mut impl Mapper<Size4KiB>) {
    let (frame, flush) = mapper.unmap(page).expect("map_to failed");
    dealloc_frame(frame);
    flush.flush();
}
