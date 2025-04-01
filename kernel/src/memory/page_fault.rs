use core::ptr;
use core::slice;

use alloc::sync::Arc;
use log::debug;
use spin::lock_api::Mutex;
use x86_64::{
    structures::{
        idt::PageFaultErrorCode,
        paging::{
            mapper::TranslateResult, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame,
            Size4KiB, Translate,
        },
    },
    PhysAddr, VirtAddr,
};

use crate::{
    constants::{memory::PAGE_SIZE, processes::MAX_FILES},
    filesys::{FileSystem, FILESYSTEM},
    memory::{
        frame_allocator::alloc_frame,
        mm::{vma_to_page_flags, Mm, VmAreaFlags},
        paging::{create_mapping, create_mapping_to_frame, get_page_flags, update_mapping},
        HHDM_OFFSET,
    },
    processes::process::{get_current_pid, PROCESS_TABLE},
    serial_println,
};

use super::mm::{VmAreaBackings, VmaChain};

/// Fault outcome enum to route what to do in IDT
pub enum FaultOutcome {
    ExistingMapping {
        page: Page<Size4KiB>,
        mapper: OffsetPageTable<'static>,
        chain: Arc<VmaChain>,
        pt_flags: PageTableFlags,
    },
    NewMapping {
        page: Page<Size4KiB>,
        mapper: OffsetPageTable<'static>,
        backing: Arc<VmAreaBackings>,
        pt_flags: PageTableFlags,
    },
    ExistingFileMapping {
        page: Page<Size4KiB>,
        mapper: OffsetPageTable<'static>,
        offset: u64,
        pt_flags: PageTableFlags,
    },
    NewFileMapping {
        page: Page<Size4KiB>,
        mapper: OffsetPageTable<'static>,
        offset: u64,
        pt_flags: PageTableFlags,
        fd: usize,
    },
    CopyOnWrite {
        page: Page<Size4KiB>,
        mapper: OffsetPageTable<'static>,
        pt_flags: PageTableFlags,
    },
    Mapped,
}

/// Determines the fault outcome by performing the bulk of the work
/// This function reads registers, sets up the mapper, finds the process,
/// locks the VMA tree, and figures out if the fault is due to a missing mapping,
/// an existing anon mapping, or a copy-on-write fault
///
/// # Arguments
/// * `error_code` - the passed in error code from the pf handler
///
/// # Returns
/// Returns a FaultOutcome enum with values that would be relevant for each function
/// This design should allow for easier debugging in the PF handler itself
pub fn determine_fault_cause(error_code: PageFaultErrorCode) -> FaultOutcome {
    use x86_64::registers::control::{Cr2, Cr3};

    // Read fault info.
    let faulting_address = Cr2::read().expect("Cannot read faulting address").as_u64();

    // Set up the page table mapper.
    let pml4 = Cr3::read().0;
    let new_pml4_phys = pml4.start_address();
    let new_pml4_virt = VirtAddr::new((*HHDM_OFFSET).as_u64()) + new_pml4_phys.as_u64();
    let new_pml4_ptr: *mut PageTable = new_pml4_virt.as_mut_ptr();
    let mut mapper =
        unsafe { OffsetPageTable::new(&mut *new_pml4_ptr, VirtAddr::new((*HHDM_OFFSET).as_u64())) };

    // Compute the faulting page.
    let page = Page::containing_address(VirtAddr::new(faulting_address));

    // Locate the current process.
    let pid = get_current_pid();
    let process = {
        let process_table = PROCESS_TABLE.read();
        process_table
            .get(&pid)
            .expect("can't find pcb in process table")
            .clone()
    };

    // Check if the page is mapped.
    let translate_result = mapper.translate(page.start_address());
    let is_mapped = match translate_result {
        TranslateResult::Mapped { .. } => true,
        TranslateResult::NotMapped => false,
        _ => panic!("Unexpected result during page translation"),
    };

    let mut outcome = None;
    unsafe {
        (*process.pcb.get()).mm.with_vma_tree(|tree| {
            // Find the VMA covering the faulting address.
            let vma_arc = Mm::find_vma(faulting_address, tree).expect("Vma not found?");
            let vma = vma_arc.lock();

            // Compute the fault's offset within the VMA.
            let fault_offset = page.start_address().as_u64() - vma.start;

            // Look up the segment covering this fault.
            // We use a range query to find the segment with the greatest key <= fault_offset.
            let segments = vma.segments.lock();
            let seg_entry = segments
                .range(..=fault_offset)
                .next_back()
                .expect("No segment found covering fault offset");
            let seg_key = *seg_entry.0;
            let segment = seg_entry.1;
            if fault_offset >= segment.end {
                panic!("Fault offset {} not covered by segment", fault_offset);
            }

            // Use the segment's backing.
            let backing = Arc::clone(&segment.backing);
            // Compute the mapping offset within the backing.
            // (Assuming each segment's reverse mappings are keyed relative to its own start.)
            let mapping_offset = fault_offset - seg_key;
            let anon_vma_chain = backing.find_mapping(mapping_offset);

            let pt_flags = vma_to_page_flags(vma.flags);

            outcome = if !is_mapped {
                // if there is a backing file
                // this check works since if there is no backing file, we set fd to usize::MAX
                // which is trivially larger than MAX_FILES
                if segment.fd < MAX_FILES {
                    let pid = get_current_pid();
                    let pcb = {
                        let process_table = PROCESS_TABLE.read();
                        process_table
                            .get(&pid)
                            .expect("can't find pcb in process table")
                            .clone()
                    };
                    let pcb = pcb.pcb.get();

                    let file = (*pcb).fd_table[segment.fd]
                        .clone()
                        .expect("No file associated with this fd.");
                    let locked_file = file.lock();
                    let page_cache = &locked_file.page_cache;
                    let file_offset = segment.pg_offset + fault_offset;
                    if page_cache.contains_key(&file_offset) {
                        Some(FaultOutcome::ExistingFileMapping {
                            page,
                            mapper,
                            offset: file_offset,
                            pt_flags,
                        })
                    } else {
                        Some(FaultOutcome::NewFileMapping {
                            page,
                            mapper,
                            offset: file_offset,
                            pt_flags,
                            fd: segment.fd,
                        })
                    }
                }
                // if there is no file backing, handle it as an anonymous page
                else if let Some(chain) = anon_vma_chain {
                    Some(FaultOutcome::ExistingMapping {
                        page,
                        mapper,
                        chain,
                        pt_flags,
                    })
                } else {
                    Some(FaultOutcome::NewMapping {
                        page,
                        mapper,
                        backing,
                        pt_flags,
                    })
                }
            } else {
                // For mapped pages, check if a Copy-On-Write fault occurred.
                let flags = get_page_flags(page, &mut mapper).expect("Could not get page flags");
                let cow = !vma.flags.contains(VmAreaFlags::SHARED);
                let caused_by_write = error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE);
                if cow && caused_by_write && flags.contains(PageTableFlags::PRESENT) {
                    Some(FaultOutcome::CopyOnWrite {
                        page,
                        mapper,
                        pt_flags,
                    })
                } else {
                    Some(FaultOutcome::Mapped)
                }
            };
        });
    }

    outcome.expect("Failed to determine fault cause")
}

/// Handles a fault by using an existing anonymous VMA chain mapping.
///
/// # Arguments
/// * `page` - the page corresponding to the faulting address
/// * `mapper` - page faulting process's page table
/// * `chain` - VmaChain that corresponds to this faulting address (offset within VMA)
/// * `pt_flags` - page table flags to update to, based on VMA flags
pub fn handle_existing_mapping(
    page: Page<Size4KiB>,
    mapper: &mut OffsetPageTable,
    chain: Arc<VmaChain>,
    pt_flags: PageTableFlags,
) {
    serial_println!("Page not mapped; using existing anon chain mapping.");
    create_mapping_to_frame(
        page,
        mapper,
        Some(pt_flags),
        PhysFrame::containing_address(PhysAddr::new(chain.file_offset_or_frame)),
    );
}

pub fn handle_existing_file_mapping(
    page: Page<Size4KiB>,
    mapper: &mut OffsetPageTable,
    offset: u64,
    pt_flags: PageTableFlags,
) {
    serial_println!("File not mapped; using existing frame mapping");
    create_mapping_to_frame(
        page,
        mapper,
        Some(pt_flags),
        PhysFrame::containing_address(PhysAddr::new(offset)),
    );
}

pub async fn handle_new_file_mapping(
    page: Page<Size4KiB>,
    mapper: &mut OffsetPageTable<'_>,
    offset: u64,
    pt_flags: PageTableFlags,
    fd: usize,
) {
    serial_println!("Creating a new mapping for a file-backed page.");

    // allocate a frame for that offset of the file
    let frame = alloc_frame().expect("Failed to allocate frame for file-backed page");

    let pid = get_current_pid();
    let pcb = {
        let process_table = PROCESS_TABLE.read();
        process_table
            .get(&pid)
            .expect("can't find pcb in process table")
            .clone()
    };
    let pcb = pcb.pcb.get();

    let file = unsafe {
        (*pcb).fd_table[fd]
            .clone()
            .expect("No file associated with this fd.")
    };

    // Store the frame in the file’s page cache
    let mut locked_file = file.lock();
    locked_file.page_cache.insert(offset, frame);

    // Create mapping between faulting page and frame
    create_mapping_to_frame(page, mapper, Some(pt_flags), frame);
    let ptr = page.start_address().as_u64() as *mut u8;
    let buffer: &mut [u8] = unsafe { slice::from_raw_parts_mut(ptr, PAGE_SIZE) };
    {

        // Now that the virtual address is mapped, use it to memcpy the file at an offset to the frame
        FILESYSTEM
            .get()
            .expect("Could not get filesystem")
            .lock()
            .read_file(fd, buffer)
            .await
            .expect("could not read file");

    }
}

/// Handles a fault by creating a new mapping and inserting it into the backing.
///
/// # Arguments
/// * `page` - the page corresponding to the faulting address
/// * `mapper` - page faulting process's page table
/// * `backing` - VmaChain that corresponds to this faulting address (offset within VMA)
/// * `pt_flags` - page table flags to update to, based on VMA flags
pub fn handle_new_mapping(
    page: Page<Size4KiB>,
    mapper: &mut OffsetPageTable,
    backing: &Arc<VmAreaBackings>,
    pt_flags: PageTableFlags,
) {
    serial_println!("Page not mapped; creating a new mapping.");
    debug!(
        "Diagnositcs:\n\tPage: {:#?}\n\tBacking: {:#?}\n\tPT Flags: {:#?}",
        page, backing, pt_flags
    );

    let mut flags = pt_flags;
    flags.set(PageTableFlags::PRESENT, true);

    let new_frame = create_mapping(page, mapper, Some(flags));
    backing.insert_mapping(Arc::new(VmaChain {
        offset: page.start_address().as_u64(),
        fd: usize::MAX,
        file_offset_or_frame: new_frame.start_address().as_u64(),
    }));
}

/// Handles a copy-on-write fault. Saves current data in a buffer
/// and then copies it over after a new frame is allocated
///
/// # Arguments
/// * `page` - the page corresponding to the faulting address
/// * `mapper` - page faulting process's page table
/// * `pt_flags` - page table flags to update to, based on VMA flags
pub fn handle_cow_fault(
    page: Page<Size4KiB>,
    mapper: &mut OffsetPageTable,
    pt_flags: PageTableFlags,
) {
    serial_println!("Handling copy-on-write fault.");
    let start = page.start_address();
    let src_ptr = start.as_mut_ptr();

    // old page data
    let mut buffer: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
    unsafe {
        ptr::copy_nonoverlapping(src_ptr, buffer.as_mut_ptr(), PAGE_SIZE);
    }

    // Allocate a new frame and update the mapping.
    let frame = alloc_frame().expect("Frame allocation failed in COW");
    update_mapping(page, mapper, frame, Some(pt_flags));

    // Copy the saved data back.
    unsafe {
        ptr::copy_nonoverlapping(buffer.as_mut_ptr(), src_ptr, PAGE_SIZE);
    }
    serial_println!("Completed copy-on-write fault handling.");
}
