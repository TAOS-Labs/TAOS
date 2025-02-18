use crate::{
    constants::{
        memory::PAGE_SIZE,
        processes::{STACK_SIZE, STACK_START},
    },
    memory::paging::{create_mapping, update_permissions},
    serial_println,
};
use core::ptr::{copy_nonoverlapping, write_bytes};
use goblin::{
    elf::Elf,
    elf64::program_header::{PF_W, PF_X, PT_LOAD},
};
use x86_64::structures::paging::OffsetPageTable;
use x86_64::{
    structures::paging::{Mapper, Page, PageTableFlags, Size4KiB},
    VirtAddr,
};

// We import our new helper
use crate::memory::paging::map_kernel_frame;

pub fn load_elf(
    elf_bytes: &[u8],
    user_mapper: &mut impl Mapper<Size4KiB>,
    kernel_mapper: &mut OffsetPageTable<'static>,
) -> (VirtAddr, u64) {
    let elf = Elf::parse(elf_bytes).expect("Parsing ELF failed");
    serial_println!("ELF parsed, entry = 0x{:x}", elf.header.e_entry);

    for (i, ph) in elf.program_headers.iter().enumerate() {
        if ph.p_type != PT_LOAD {
            continue;
        }

        let virt_addr = VirtAddr::new(ph.p_vaddr);
        let mem_size = ph.p_memsz as usize;
        let file_size = ph.p_filesz as usize;
        let offset = ph.p_offset as usize;

        serial_println!(
            "Segment {}: vaddr=0x{:x}, mem_size={}, file_size={}, offset=0x{:x}",
            i,
            ph.p_vaddr,
            mem_size,
            file_size,
            offset
        );

        let start_page = Page::containing_address(virt_addr);
        let end_page = Page::containing_address(virt_addr + (mem_size - 1) as u64);

        // Build final page flags
        // FIXME: Update flags correctly this cant be writable by default!
        let default_flags =
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE;
        let mut flags = default_flags;
        if (ph.p_flags & PF_W) != 0 {
            flags |= PageTableFlags::WRITABLE;
        }
        if (ph.p_flags & PF_X) == 0 {
            flags |= PageTableFlags::NO_EXECUTE;
        }

        // For each page in [start_page..end_page], create user mapping,
        // then do a kernel alias to copy data in
        for page in Page::range_inclusive(start_page, end_page) {
            let frame = create_mapping(page, user_mapper, Some(default_flags));
            let kernel_alias = map_kernel_frame(kernel_mapper, frame, flags);
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

            unsafe {
                update_permissions(page, user_mapper, flags);
            }
        }

        serial_println!("Segment {} loaded successfully.", i);
    }

    // Map user stack
    let stack_start = VirtAddr::new(STACK_START);
    let stack_end = VirtAddr::new(STACK_START + STACK_SIZE as u64);
    let start_page = Page::containing_address(stack_start);
    let end_page = Page::containing_address(stack_end);

    serial_println!(
        "Mapping user stack at [0x{:x}..0x{:x})",
        stack_start.as_u64(),
        stack_end.as_u64()
    );

    let stack_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    for page in Page::range_inclusive(start_page, end_page) {
        create_mapping(page, user_mapper, Some(stack_flags));
    }

    serial_println!("User stack mapped.  SP=0x{:x}", stack_end.as_u64());

    (stack_end, elf.header.e_entry)
}
