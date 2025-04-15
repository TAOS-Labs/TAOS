use core::cmp::{max, min};

use alloc::sync::Arc;
use bitflags::bitflags;
use x86_64::{
    structures::paging::{Mapper, OffsetPageTable, Page, PageTable},
    VirtAddr,
};

use crate::{
    constants::memory::PAGE_SIZE,
    events::{current_running_event_info, EventInfo},
    memory::{
        mm::{vma_to_page_flags, Mm, VmAreaBackings, VmAreaFlags},
        paging::{remove_mapping, update_permissions},
        HHDM_OFFSET,
    },
    processes::process::PROCESS_TABLE,
    serial_println,
};

// See https://www.man7.org/linux/man-pages/man2/mmap.2.html
bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct MmapFlags: u64 {
        const MAP_SHARED = 1 << 0;
        const MAP_SHARED_VALIDATE = 1 << 1;
        const MAP_PRIVATE = 1 << 2;
        const MAP_32BIT = 1 << 3;
        const MAP_ANONYMOUS = 1 << 4;
        const MAP_ANON = 1 << 4;
        const MAP_DENYWRITE = 1 << 5;
        const MAP_EXECUTABLE = 1 << 6;
        const MAP_FILE = 1 << 7;
        const MAP_FIXED = 1 << 8;
        const MAP_FIXED_NOREPLACE = 1 << 9;
        const MAP_GROWSDOWN = 1 << 10;
        const MAP_HUGETLB = 1 << 11;
        const MAP_HUGE_2MB = 1 << 12;
        const MAP_HUGE_1GB = 1 << 13;
        const MAP_LOCKED = 1 << 14;
        const MAP_NONBLOCK = 1 << 15;
        const MAP_NORESERVE = 1 << 16;
        const MAP_POPULATE = 1 << 17;
        const MAP_STACK = 1 << 18;
        const MAP_SYNC = 1 << 19;
        const MAP_UNINITIALIZED = 1 << 20;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ProtFlags: u64 {
        const PROT_NONE = 0;
        const PROT_READ = 1 << 0;
        const PROT_WRITE = 1 << 1;
        const PROT_EXEC = 1 << 2;
        const PROT_SEM = 1 << 3;
        const PROT_SAO = 1 << 4;
        const PROT_GROWSUP = 1 << 5;
        const PROT_GROWSDOWN = 1 << 6;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MmapErrors {
    EACCES,
    EAGAIN,
    EBADF,
    EEXIST,
    EINVAL,
    ENFILE,
    ENODEV,
    ENOMEM,
    EOVERFLOW,
    EPERM,
    ETXTBSY,
    SIGSEGV,
    SIGBUS,
}

pub fn prot_to_vma_flags(prot: u64, vma_flags: VmAreaFlags) -> VmAreaFlags {
    let mut flags = vma_flags;
    // Remove any existing permission bits (WRITABLE, EXECUTE, and GROWS_DOWN)
    flags.remove(VmAreaFlags::WRITABLE);
    flags.remove(VmAreaFlags::EXECUTE);
    flags.remove(VmAreaFlags::GROWS_DOWN);

    if prot & ProtFlags::PROT_WRITE.bits() != 0 {
        flags.insert(VmAreaFlags::WRITABLE);
    }
    if prot & ProtFlags::PROT_EXEC.bits() != 0 {
        flags.insert(VmAreaFlags::EXECUTE);
    }
    if prot & ProtFlags::PROT_GROWSDOWN.bits() != 0 {
        flags.insert(VmAreaFlags::GROWS_DOWN);
    }

    flags
}

// Helper function to convert mmap flags (and prot) to VmAreaFlags.
pub fn mmap_prot_to_vma_flags(prot: u64, mmap_flags: MmapFlags) -> VmAreaFlags {
    let mut vma_flags = VmAreaFlags::empty();

    // Set writable/executable based on the prot flags.
    if prot & ProtFlags::PROT_WRITE.bits() != 0 {
        vma_flags.set(VmAreaFlags::WRITABLE, true);
    }
    if prot & ProtFlags::PROT_EXEC.bits() != 0 {
        vma_flags.set(VmAreaFlags::EXECUTE, true);
    }

    // Shared vs. private: if MAP_SHARED is set, mark as SHARED.
    if mmap_flags.contains(MmapFlags::MAP_SHARED) {
        vma_flags.set(VmAreaFlags::SHARED, true);
    }
    // For MAP_PRIVATE, we leave it as non-shared (copy-on-write semantics).

    if mmap_flags.contains(MmapFlags::MAP_GROWSDOWN) {
        vma_flags.set(VmAreaFlags::GROWS_DOWN, true);
    }

    if mmap_flags.contains(MmapFlags::MAP_LOCKED) {
        vma_flags.set(VmAreaFlags::LOCKED, true);
    }

    if mmap_flags.contains(MmapFlags::MAP_NORESERVE) {
        vma_flags.set(VmAreaFlags::NORESERVE, true);
    }

    if mmap_flags.contains(MmapFlags::MAP_HUGETLB) {
        vma_flags.set(VmAreaFlags::HUGEPAGE, true);
    }

    if mmap_flags.contains(MmapFlags::MAP_FIXED) {
        vma_flags.set(VmAreaFlags::FIXED, true);
    }

    if mmap_flags.contains(MmapFlags::MAP_FILE) {
        vma_flags.set(VmAreaFlags::MAPPED_FILE, true);
    }

    vma_flags
}

pub fn sys_mmap(_addr: u64, len: u64, prot: u64, flags: u64, fd: i64, offset: u64) -> u64 {
    // Basic sanity check.
    if len == 0 {
        serial_println!("Zero length mapping");
        panic!("mmap called with zero length");
    }
    serial_println!("Fd is {}", fd);

    let event: EventInfo = current_running_event_info();
    let pid = event.pid;

    // For testing we hardcode to one for now.
    let process_table = PROCESS_TABLE.write();
    let process = process_table
        .get(&pid)
        .expect("Could not get pcb from process table");
    let pcb = process.pcb.get();
    let begin_addr = unsafe { (*pcb).mmap_address };
    let addr_to_return = begin_addr;
    let vma_backing = VmAreaBackings::new();

    // Make sure we have enough virtual space.
    if begin_addr + len > (*HHDM_OFFSET).as_u64() {
        serial_println!("Ran out of virtual memory for mmap call.");
        return 0;
    }

    // Create an instance of MmapFlags from the raw flags.
    let mmap_flags = MmapFlags::from_bits_truncate(flags);
    // Compute the VMA flags using our helper.
    let vma_flags = mmap_prot_to_vma_flags(prot, mmap_flags);

    // Insert the new VMA into the process's VMA tree.
    unsafe {
        (*pcb).mm.with_vma_tree_mutable(|tree| {
            let _ = Mm::insert_vma(
                tree,
                begin_addr,
                begin_addr + len,
                Arc::new(vma_backing),
                vma_flags,
                fd as usize,
                offset,
            );
        })
    }

    serial_println!("Finished mmap call");
    addr_to_return
}

/// Handler to change protection of a region of mapped memory
///
/// There is no guarantee that the address given is nice about
/// being in a VMA (Could be inside of an existing one, could be
/// spanning multiple, etc.)
///
/// It is guaranteed that addr is page aligned
/// It is NOT guaranteed that len is page aligned
///
/// # Arguments
/// * `addr` - the starting virtual address of mapped memory, page aligned
/// * `len`  - the length of the region of memory we want to update
/// * `prot` - the protection we want to updatge to; corresponds to VMA flags
pub fn sys_mprotect(addr: u64, len: u64, prot: u64) -> u64 {
    // Round the end address up to a page boundary.
    let end_addr = (addr + len).div_ceil(PAGE_SIZE as u64) * PAGE_SIZE as u64;

    let event: EventInfo = current_running_event_info();
    let pid = event.pid;

    let process_table = PROCESS_TABLE.write();
    let process = process_table
        .get(&pid)
        .expect("Could not get pcb from process table");
    let pcb = process.pcb.get();

    let err = unsafe {
        let new_pml4_phys = (*pcb).mm.pml4_frame.start_address();
        let new_pml4_virt = VirtAddr::new((*HHDM_OFFSET).as_u64()) + new_pml4_phys.as_u64();
        let new_pml4_ptr: *mut PageTable = new_pml4_virt.as_mut_ptr();
        let mut mapper =
            OffsetPageTable::new(&mut *new_pml4_ptr, VirtAddr::new((*HHDM_OFFSET).as_u64()));

        (*pcb).mm.with_vma_tree_mutable(|tree| {
            let mut current_address = addr;

            while current_address < end_addr {
                // Use current_address so that we progress through the unmap range
                if let Some(vma) = Mm::find_vma(current_address, tree) {
                    let (vma_start, vma_end) = {
                        let v = vma.lock();
                        (v.start, v.end)
                    };

                    // Compute the overlap between this VMA and the unmap request
                    let unmap_start = max(vma_start, addr);
                    let unmap_end = min(vma_end, end_addr);

                    // call shrink_vma to split the vma into three portions:
                    // left: [vma_start, unmap_start)
                    // middle: [unmap_start, unmap_end)
                    // right: [unmap_end, vma_end)
                    let (left_opt, middle_opt, right_opt) =
                        Mm::shrink_vma(vma_start, unmap_start, unmap_end, tree);

                    // now, decide which portions fall within the unmap region and should be removed
                    // (if a split portion lies entirely inside [addr, end_addr), it should be unmapped)
                    if let Some(left_vma) = left_opt {
                        let (l_start, l_end, l_flags) = {
                            let l = left_vma.lock();
                            (l.start, l.end, l.flags)
                        };
                        if l_start >= addr && l_end <= end_addr {
                            let new_flags = prot_to_vma_flags(prot, l_flags);
                            for page in Page::range_inclusive(
                                Page::containing_address(VirtAddr::new(l_start)),
                                Page::containing_address(VirtAddr::new(l_end)),
                            ) {
                                if mapper.translate_page(page).is_ok() {
                                    update_permissions(
                                        page,
                                        &mut mapper,
                                        vma_to_page_flags(new_flags),
                                    );
                                }
                            }
                            Mm::update_vma_permissions(&left_vma, new_flags);
                            Mm::coalesce_vma(left_vma, tree);
                        }
                    }
                    // if right_opt exists and its region is completely within [addr, end_addr]
                    if let Some(right_vma) = right_opt {
                        let (r_start, r_end, r_flags) = {
                            let r = right_vma.lock();
                            (r.start, r.end, r.flags)
                        };
                        let new_flags = prot_to_vma_flags(prot, r_flags);
                        if r_start >= addr && r_end <= end_addr {
                            for page in Page::range_inclusive(
                                Page::containing_address(VirtAddr::new(r_start)),
                                Page::containing_address(VirtAddr::new(r_end)),
                            ) {
                                if mapper.translate_page(page).is_ok() {
                                    update_permissions(
                                        page,
                                        &mut mapper,
                                        vma_to_page_flags(new_flags),
                                    );
                                }
                            }
                            Mm::update_vma_permissions(&right_vma, new_flags);
                            Mm::coalesce_vma(right_vma, tree);
                        }
                    }
                    // finally, if the entire vma is within [addr, end_addr], then the surviving portion (middle)
                    // is also to be removed.
                    if let Some(middle_vma) = middle_opt {
                        let (m_start, m_end, m_flags) = {
                            let m = middle_vma.lock();
                            (m.start, m.end, m.flags)
                        };
                        let new_flags = prot_to_vma_flags(prot, m_flags);
                        if m_start >= addr && m_end <= end_addr {
                            for page in Page::range_inclusive(
                                Page::containing_address(VirtAddr::new(m_start)),
                                Page::containing_address(VirtAddr::new(m_end)),
                            ) {
                                if mapper.translate_page(page).is_ok() {
                                    update_permissions(
                                        page,
                                        &mut mapper,
                                        vma_to_page_flags(new_flags),
                                    );
                                }
                            }
                            Mm::update_vma_permissions(&middle_vma, new_flags);
                            Mm::coalesce_vma(middle_vma, tree);
                        }
                    }

                    current_address = unmap_end;
                } else {
                    break;
                }
            }
            1
        })
    };

    err
}

pub fn sys_munmap(addr: u64, len: u64) -> u64 {
    // Round the end address up to a page boundary.
    let end_addr = (addr + len).div_ceil(PAGE_SIZE as u64) * PAGE_SIZE as u64;

    let event: EventInfo = current_running_event_info();
    let pid = event.pid;

    let process_table = PROCESS_TABLE.write();
    let process = process_table
        .get(&pid)
        .expect("Could not get pcb from process table");
    let pcb = process.pcb.get();

    let err = unsafe {
        let new_pml4_phys = (*pcb).mm.pml4_frame.start_address();
        let new_pml4_virt = VirtAddr::new((*HHDM_OFFSET).as_u64()) + new_pml4_phys.as_u64();
        let new_pml4_ptr: *mut PageTable = new_pml4_virt.as_mut_ptr();
        let mut mapper =
            OffsetPageTable::new(&mut *new_pml4_ptr, VirtAddr::new((*HHDM_OFFSET).as_u64()));

        (*pcb).mm.with_vma_tree_mutable(|tree| {
            let mut current_address = addr;

            while current_address < end_addr {
                // Use current_address so that we progress through the unmap range
                if let Some(vma) = Mm::find_vma(current_address, tree) {
                    let (vma_start, vma_end) = {
                        let v = vma.lock();
                        (v.start, v.end)
                    };

                    // Compute the overlap between this VMA and the unmap request
                    let unmap_start = max(vma_start, addr);
                    let unmap_end = min(vma_end, end_addr);

                    // call shrink_vma to split the vma into three portions:
                    // left: [vma_start, unmap_start)
                    // middle: [unmap_start, unmap_end)
                    // right: [unmap_end, vma_end)
                    let (left_opt, middle_opt, right_opt) =
                        Mm::shrink_vma(vma_start, unmap_start, unmap_end, tree);

                    // now, decide which portions fall within the unmap region and should be removed
                    // (if a split portion lies entirely inside [addr, end_addr), it should be unmapped)
                    if let Some(left_vma) = left_opt {
                        let (l_start, l_end) = {
                            let l = left_vma.lock();
                            (l.start, l.end)
                        };
                        if l_start >= addr && l_end <= end_addr {
                            for page in Page::range_inclusive(
                                Page::containing_address(VirtAddr::new(l_start)),
                                Page::containing_address(VirtAddr::new(l_end)),
                            ) {
                                remove_mapping(page, &mut mapper);
                            }
                            Mm::remove_vma(l_start, tree);
                        }
                    }
                    // if right_opt exists and its region is completely within [addr, end_addr]
                    if let Some(right_vma) = right_opt {
                        let (r_start, r_end) = {
                            let r = right_vma.lock();
                            (r.start, r.end)
                        };
                        if r_start >= addr && r_end <= end_addr {
                            for page in Page::range_inclusive(
                                Page::containing_address(VirtAddr::new(r_start)),
                                Page::containing_address(VirtAddr::new(r_end)),
                            ) {
                                remove_mapping(page, &mut mapper);
                            }
                            Mm::remove_vma(r_start, tree);
                        }
                    }
                    // finally, if the entire vma is within [addr, end_addr], then the surviving portion (middle)
                    // is also to be removed.
                    if let Some(middle_vma) = middle_opt {
                        let (m_start, m_end) = {
                            let m = middle_vma.lock();
                            (m.start, m.end)
                        };
                        if m_start >= addr && m_end <= end_addr {
                            for page in Page::range_inclusive(
                                Page::containing_address(VirtAddr::new(m_start)),
                                Page::containing_address(VirtAddr::new(m_end)),
                            ) {
                                remove_mapping(page, &mut mapper);
                            }
                            Mm::remove_vma(m_start, tree);
                        }
                    }

                    current_address = unmap_end;
                } else {
                    break;
                }
            }
            1
        })
    };

    err
}

// TODO: Mmap tests
#[cfg(test)]
mod tests {
    use crate::{
        constants::processes::{
            TEST_MMAP_ANON_SHARED, TEST_MMAP_CHILD_WRITES, TEST_MPROTECT_CHILD_WRITES,
        }, events::schedule_process, processes::process::create_process, serial_println, syscalls::syscall_handlers::REGISTER_VALUES
    };

    use crate::events::{current_running_event, futures::await_on::AwaitProcess, get_runner_time};

    #[test_case]
    async fn mmap_anonymous_shared() {
        let pid = create_process(TEST_MMAP_ANON_SHARED);
        schedule_process(pid);

        let waiter = AwaitProcess::new(
            pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        )
        .await;

        assert!(waiter.is_ok());
        let reg_values = REGISTER_VALUES.lock();
        let reg_vals_on_exit = reg_values.get(&pid).expect("No process found.");
        assert_eq!(reg_vals_on_exit.r8, 'A' as u64);
        assert_eq!(reg_vals_on_exit.r9, 'B' as u64);
        assert_eq!(reg_vals_on_exit.r10, 'C' as u64);
    }

    #[test_case]
    async fn mmap_anonymous_child_writes_first() {
        let pid = create_process(TEST_MMAP_CHILD_WRITES);
        schedule_process(pid);

        let waiter = AwaitProcess::new(
            pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        )
        .await;

        assert!(waiter.is_ok());
        let reg_values = REGISTER_VALUES.lock();
        let reg_vals_on_exit = reg_values.get(&pid).expect("No process found.");
        assert_eq!(reg_vals_on_exit.r8, 'X' as u64);
        assert_eq!(reg_vals_on_exit.r9, 'Y' as u64);
        assert_eq!(reg_vals_on_exit.r10, 'Z' as u64);
    }

    #[test_case]
    async fn mprotect_child_writes() {
        let pid = create_process(TEST_MPROTECT_CHILD_WRITES);
        schedule_process(pid);

        let waiter = AwaitProcess::new(
            pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        )
        .await;

        assert!(waiter.is_ok());
        let reg_values = REGISTER_VALUES.lock();
        let reg_vals_on_exit = reg_values.get(&pid).expect("No process found.");
        assert_eq!(reg_vals_on_exit.r8, 'X' as u64);
        assert_eq!(reg_vals_on_exit.r9, 'Y' as u64);
        assert_eq!(reg_vals_on_exit.r10, 'Z' as u64);
    }
}
