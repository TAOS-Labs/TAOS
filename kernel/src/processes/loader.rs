use crate::{
    constants::{
        memory::PAGE_SIZE,
        processes::{STACK_SIZE, STACK_START},
    },
    memory::{
        frame_allocator::with_generic_allocator,
        mm::{Mm, VmAreaBackings, VmAreaFlags},
        paging::{create_mapping, create_mapping_to_frame, update_permissions},
    },
    serial_print, serial_println,
};
use alloc::{string::String, sync::Arc, vec::Vec};
use core::ptr::{copy_nonoverlapping, write_bytes};
use goblin::{
    elf::{Elf, ProgramHeader},
    elf64::program_header::{PF_W, PF_X, PT_LOAD, PT_TLS},
};
use x86_64::{
    structures::paging::{
        mapper::CleanUp, Mapper, OffsetPageTable, Page, PageTableFlags, Size4KiB,
    },
    VirtAddr,
};

// We import our new helper
use crate::memory::paging::map_kernel_frame;

use super::process::PCB;

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
    pcb: &mut PCB,
    elf_bytes: &[u8],
    user_mapper: &mut impl Mapper<Size4KiB>,
    kernel_mapper: &mut OffsetPageTable<'static>,
    args: Vec<String>,
    envs: Vec<String>,
) -> (VirtAddr, u64) {
    let elf = Elf::parse(elf_bytes).expect("Parsing ELF failed");
    let mut tls_ph: Option<&ProgramHeader> = None;
    let mut phdr_runtime: u64 = 0; // will hold VA of the phdr table

    for ph in elf.program_headers.iter() {
        match ph.p_type {
            PT_LOAD => {
                let virt_addr = VirtAddr::new(ph.p_vaddr);
                if ph.p_offset == 0 && phdr_runtime == 0 {
                    // this PT_LOAD starts at file off 0, so load_base = virt_addr
                    phdr_runtime = virt_addr.as_u64() + elf.header.e_phoff as u64;
                }

                let mem_size = ph.p_memsz as usize;
                let file_size = ph.p_filesz as usize;
                let offset = ph.p_offset as usize;

                let start_page = Page::containing_address(virt_addr);
                let end_page = Page::containing_address(virt_addr + (mem_size - 1) as u64);

                // Build final page flags
                let default_flags = PageTableFlags::PRESENT
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::WRITABLE;
                let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;

                let anon_vma_code_and_data = Arc::new(VmAreaBackings::new());

                // For each page in [start_page..end_page], create user mapping,
                // then do a kernel alias to copy data in
                for page in Page::range_inclusive(start_page, end_page) {
                    let frame = create_mapping(page, user_mapper, Some(default_flags));
                    let kernel_alias = map_kernel_frame(kernel_mapper, frame, default_flags);
                    // now `kernel_alias` is a kernel virtual address of that same frame

                    let page_offset = page
                        .start_address()
                        .as_u64()
                        .saturating_sub(start_page.start_address().as_u64())
                        as usize;
                    let page_remaining = PAGE_SIZE - (page_offset % PAGE_SIZE);
                    let to_copy =
                        core::cmp::min(file_size.saturating_sub(page_offset), page_remaining);

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

                    pcb.mm.with_vma_tree_mutable(|tree| {
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

                    update_permissions(page, user_mapper, flags);

                    let unmap_page: Page<Size4KiB> = Page::containing_address(kernel_alias);
                    // unmap the frame, but do not actually deallocate it
                    // the physical frame is still used by the process in its own mapping
                    kernel_mapper
                        .unmap(unmap_page)
                        .expect("Unmapping kernel frame failed")
                        .1
                        .flush();
                    with_generic_allocator(|allocator| unsafe {
                        kernel_mapper.clean_up(allocator)
                    });

                    update_permissions(page, user_mapper, flags);
                }
            }

            PT_TLS => {
                tls_ph = Some(ph);
            }

            _ => {}
        }
    }
    if let Some(ph) = tls_ph {
        let tls_p_vaddr = ph.p_vaddr;
        let tls_memsz = ph.p_memsz as usize;
        let tls_filesz = ph.p_filesz as usize;
        let tls_align = ph.p_align as u64;

        // round up for tp_offset
        let tp_offset =
            ((tls_filesz + (tls_align as usize) - 1) / (tls_align as usize)) * (tls_align as usize);

        let template_start = VirtAddr::new(tls_p_vaddr);

        // decide static vs dynamic
        let is_static = user_mapper
            .translate_page(Page::containing_address(template_start))
            .is_ok();
        if is_static {
            let tls_start = VirtAddr::new(ph.p_vaddr);
            let tls_memsz = ph.p_memsz as usize;
            let tls_filesz = ph.p_filesz as usize;
            let tls_align = ph.p_align as u64;

            // compute where FS:0 / FS:8 go
            let tp_offset =
                ((tls_filesz + tls_align as usize - 1) / tls_align as usize) * tls_align as usize;
            let tcb_base = tls_start.as_u64() + tp_offset as u64;
            let dtv_base = tcb_base + 16;

            // cover both the TCB and the DTV slots
            let first = Page::containing_address(VirtAddr::new(tcb_base));
            let last = Page::containing_address(VirtAddr::new(dtv_base + 15));

            let flags = PageTableFlags::PRESENT
                | PageTableFlags::USER_ACCESSIBLE
                | PageTableFlags::WRITABLE;

            for page in Page::range_inclusive(first, last) {
                let phys = user_mapper
                    .translate_page(page)
                    .expect("static TLS page not mapped");

                // 2) alias it in the kernel so we can write it
                let kalias = map_kernel_frame(kernel_mapper, phys, flags);
                let kbase = kalias.as_u64();
                let ubase = page.start_address().as_u64();

                // helper: turn a user-VA into a kernel pointer
                let tocptr = |user_va: u64| -> *mut u64 { (kbase + (user_va - ubase)) as *mut u64 };

                // 3) if this page contains the TCB area, write FS:0 and FS:8
                if (ubase..ubase + PAGE_SIZE as u64).contains(&tcb_base) {
                    unsafe {
                        tocptr(tcb_base).write_volatile(tcb_base);
                        tocptr(tcb_base + 8).write_volatile(dtv_base);
                    }
                }

                // 4) if it contains the DTV, write DTV[0]=1 and DTV[1]=tls_start
                if (ubase..ubase + PAGE_SIZE as u64).contains(&dtv_base) {
                    unsafe {
                        tocptr(dtv_base).write_volatile(1);
                        tocptr(dtv_base + 8).write_volatile(tls_start.as_u64());
                    }
                }

                let unmap_pg: Page<Size4KiB> = Page::containing_address(kalias);
                kernel_mapper.unmap(unmap_pg).unwrap().1.flush();
                with_generic_allocator(|a| unsafe { kernel_mapper.clean_up(a) });
            }

            pcb.fs_base = tcb_base;
            serial_println!("STATIC TLS → fs_base = {:#x}", pcb.fs_base);
        } else {
            // ── DYNAMIC TLS ───────────────────────────────────────────────────
        }
    }

    // Map user stack
    let stack_start = VirtAddr::new(STACK_START);
    let stack_end = VirtAddr::new(STACK_START + STACK_SIZE as u64);
    let start_page: Page<Size4KiB> = Page::containing_address(stack_start);
    let end_page: Page<Size4KiB> = Page::containing_address(stack_end);

    for page in Page::range_inclusive(start_page, end_page) {
        let frame = create_mapping(
            page,
            user_mapper,
            Some(
                PageTableFlags::PRESENT
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::WRITABLE,
            ),
        );
        create_mapping_to_frame(
            page,
            kernel_mapper,
            Some(
                PageTableFlags::PRESENT
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::WRITABLE,
            ),
            frame,
        );
    }
    // new anon_vma that corresponds to this stack
    let anon_vma_stack = Arc::new(VmAreaBackings::new());

    pcb.mm.with_vma_tree_mutable(|tree| {
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

    // 1) start at top of the stack space
    let mut sp = VirtAddr::new(STACK_START + STACK_SIZE as u64);
    // 2) align down to 16 bytes
    sp = VirtAddr::new(sp.as_u64() & !0xF);

    // --- helper to push a C‐string and return its user‐VA ---
    let mut push_cstr = |bytes: &[u8]| -> u64 {
        // make room for the string + NUL (no extra alignment here)
        let len = bytes.len() as u64 + 1;
        sp = VirtAddr::new(sp.as_u64() - len);
        unsafe {
            let dst = sp.as_mut_ptr::<u8>();
            copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
            dst.add(bytes.len()).write(0);
        }
        sp.as_u64()
    };

    // 3) copy args/envs **backwards**, record their pointers
    let mut argv_ptrs: Vec<u64> = args.iter().rev().map(|s| push_cstr(s.as_bytes())).collect();
    let mut env_ptrs: Vec<u64> = envs.iter().rev().map(|s| push_cstr(s.as_bytes())).collect();
    argv_ptrs.reverse();
    env_ptrs.reverse();

    // 4) carve out 16 bytes for AT_RANDOM
    sp = VirtAddr::new((sp.as_u64() - 16) & !0xF);
    unsafe {
        write_bytes(sp.as_mut_ptr::<u8>(), 0xAA, 16);
    }
    let rand_ptr = sp.as_u64();

    // 5) helper to push a u64
    let mut push64 = |val: u64| {
        sp = VirtAddr::new(sp.as_u64() - 8);
        unsafe {
            sp.as_mut_ptr::<u64>().write(val);
        }
    };

    // 6) AUX-VECTOR (forward order, so AT_NULL ends up highest in the auxv):
    const AT_NULL: u64 = 0;
    const AT_RANDOM: u64 = 25;
    const AT_PAGESZ: u64 = 6;
    const AT_PHDR: u64 = 3;
    const AT_PHENT: u64 = 4;
    const AT_PHNUM: u64 = 5;

    // push AT_NULL first
    push64(0);
    push64(AT_NULL);
    // push AT_RANDOM
    push64(rand_ptr);
    push64(AT_RANDOM);
    // push page size
    push64(PAGE_SIZE as u64);
    push64(AT_PAGESZ);
    // push program‐header table info
    push64(elf.header.e_phnum as u64);
    push64(AT_PHNUM);
    push64(core::mem::size_of::<ProgramHeader>() as u64);
    push64(AT_PHENT);
    // phdr_runtime was computed above when mapping PT_LOAD at p_offset=0
    serial_println!("PHDR runtime: {}", phdr_runtime);
    push64(phdr_runtime);
    push64(AT_PHDR);

    // 7) envp pointers (NULL‐terminated)
    push64(0);
    for &p in env_ptrs.iter().rev() {
        push64(p);
    }

    // 8) argv pointers (NULL‐terminated)
    push64(0);
    for &p in argv_ptrs.iter().rev() {
        push64(p);
    }

    // 9) finally, argc
    push64(argv_ptrs.len() as u64);

    // 10) realign to 16‐byte boundary before entry
    sp = VirtAddr::new(sp.as_u64() & !0xF);

    // hand back (sp, entry_point)
    (sp, elf.header.e_entry)
}
