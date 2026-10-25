use crate::{
    constants::{
        memory::PAGE_SIZE,
        processes::{STACK_SIZE, STACK_START},
    },
    memory::{
        frame_allocator::with_generic_allocator,
        mm::{Mm, VmAreaBackings, VmAreaFlags},
        paging::{create_mapping, update_permissions},
    },
};
use alloc::sync::Arc;
use core::ptr::{copy_nonoverlapping, write_bytes};
use goblin::{
    elf::Elf,
    elf64::program_header::{PF_W, PF_X, PT_LOAD},
};
use x86_64::{
    structures::paging::{
        mapper::CleanUp, Mapper, OffsetPageTable, Page, PageTableFlags, Size4KiB,
    },
    VirtAddr,
};

// We import our new helper
use crate::memory::paging::map_kernel_frame;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderError {
    InvalidElf,
    InvalidSegment,
    UnmapFailed,
}

/// Function for initializing addresss space for process using ELF executable
///
/// # Arguments:
/// * 'elf_bytes' - byte stream of ELF executable to parse
/// * 'user_mapper' - Page table for user that maps VAs from section headers to frames
/// * 'kernel mapper' - kernel page table for mapping VAs to frames for writing ELF metadata to frames
/// * 'mm' - The process' mm struct for access to the VMAs
///
/// # Returns:
/// Virtual address of the top of user stack and entry point for process
pub fn load_elf(
    elf_bytes: &[u8],
    user_mapper: &mut impl Mapper<Size4KiB>,
    kernel_mapper: &mut OffsetPageTable<'static>,
    mm: &mut Mm,
) -> Result<(VirtAddr, u64), LoaderError> {
    let elf = Elf::parse(elf_bytes).map_err(|_| LoaderError::InvalidElf)?;
    for ph in elf.program_headers.iter() {
        if ph.p_type != PT_LOAD {
            continue;
        }

        let mem_size = ph.p_memsz as usize;
        let file_size = ph.p_filesz as usize;
        let offset = ph.p_offset as usize;

        if mem_size == 0 {
            continue;
        }
        if file_size > mem_size
            || offset
                .checked_add(file_size)
                .is_none_or(|end| end > elf_bytes.len())
        {
            return Err(LoaderError::InvalidSegment);
        }

        let virt_addr = VirtAddr::try_new(ph.p_vaddr).map_err(|_| LoaderError::InvalidSegment)?;
        let last_addr = ph
            .p_vaddr
            .checked_add((mem_size - 1) as u64)
            .ok_or(LoaderError::InvalidSegment)?;
        let end_addr = VirtAddr::try_new(last_addr).map_err(|_| LoaderError::InvalidSegment)?;

        let start_page = Page::containing_address(virt_addr);
        let end_page = Page::containing_address(end_addr);

        // Build final page flags
        let default_flags =
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE;
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;

        let anon_vma_code_and_data = Arc::new(VmAreaBackings::new());

        // For each page in [start_page..end_page], create user mapping,
        // then do a kernel alias to copy data in
        for page in Page::range_inclusive(start_page, end_page) {
            let frame = create_mapping(page, user_mapper, Some(default_flags))
                .map_err(|_| LoaderError::UnmapFailed)?;
            let kernel_alias = map_kernel_frame(kernel_mapper, frame, default_flags)
                .map_err(|_| LoaderError::UnmapFailed)?;
            // now `kernel_alias` is a kernel virtual address of that same frame

            let page_offset =
                page.start_address()
                    .as_u64()
                    .saturating_sub(start_page.start_address().as_u64()) as usize;
            let page_remaining = PAGE_SIZE - (page_offset % PAGE_SIZE);
            let to_copy = core::cmp::min(file_size.saturating_sub(page_offset), page_remaining);

            if to_copy > 0 {
                let dest = kernel_alias.as_mut_ptr::<u8>();
                let src = &elf_bytes[offset + page_offset..offset + page_offset + to_copy];
                unsafe {
                    copy_nonoverlapping(src.as_ptr(), dest, to_copy);
                }
            }

            let bss_start = file_size.saturating_sub(page_offset);
            if bss_start < page_remaining {
                // i.e. if this page has some leftover space beyond file_size
                let zero_offset_in_page = core::cmp::max(bss_start, 0);
                let zero_len = page_remaining.saturating_sub(zero_offset_in_page);
                if zero_len > 0 {
                    unsafe {
                        let dest = kernel_alias.as_mut_ptr::<u8>().add(zero_offset_in_page);
                        write_bytes(dest, 0, zero_len);
                    }
                }
            }

            let mut vma_flags = VmAreaFlags::empty();
            if (ph.p_flags & PF_W) != 0 {
                flags |= PageTableFlags::WRITABLE;
                vma_flags |= VmAreaFlags::WRITABLE;
            }
            if (ph.p_flags & PF_X) == 0 {
                flags |= PageTableFlags::NO_EXECUTE;
            } else {
                vma_flags |= VmAreaFlags::EXECUTE;
            }

            mm.with_vma_tree_mutable(|tree| {
                Mm::insert_vma(
                    tree,
                    page.start_address().as_u64(),
                    page.start_address().as_u64() + PAGE_SIZE as u64,
                    anon_vma_code_and_data.clone(),
                    vma_flags,
                    usize::MAX,
                    0,
                );
            });

            update_permissions(page, user_mapper, flags).map_err(|_| LoaderError::UnmapFailed)?;

            let unmap_page: Page<Size4KiB> = Page::containing_address(kernel_alias);
            // unmap the frame, but do not actually deallocate it
            // the physical frame is still used by the process in its own mapping
            kernel_mapper
                .unmap(unmap_page)
                .map_err(|_| LoaderError::UnmapFailed)?
                .1
                .flush();
            with_generic_allocator(|allocator| unsafe { kernel_mapper.clean_up(allocator) })
                .ok_or(LoaderError::UnmapFailed)?;

            update_permissions(page, user_mapper, flags).map_err(|_| LoaderError::UnmapFailed)?;
        }
    }

    // Map user stack
    let stack_start = VirtAddr::new(STACK_START);
    let stack_end = VirtAddr::new(STACK_START + STACK_SIZE as u64);
    let _start_page: Page<Size4KiB> = Page::containing_address(stack_start);
    let _end_page: Page<Size4KiB> = Page::containing_address(stack_end);

    // new anon_vma that corresponds to this stack
    let anon_vma_stack = Arc::new(VmAreaBackings::new());

    mm.with_vma_tree_mutable(|tree| {
        Mm::insert_vma(
            tree,
            STACK_START,
            STACK_START + STACK_SIZE as u64,
            anon_vma_stack,
            VmAreaFlags::WRITABLE | VmAreaFlags::GROWS_DOWN,
            usize::MAX,
            0,
        );
    });

    Ok((stack_end, elf.header.e_entry))
}
