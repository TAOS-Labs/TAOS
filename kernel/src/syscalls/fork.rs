use core::{ptr, sync::atomic::Ordering};

use alloc::sync::Arc;
use x86_64::{
    structures::paging::{OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame},
    VirtAddr,
};

use crate::{
    constants::memory::PAGE_SIZE,
    events::{current_running_event_info, schedule_process},
    interrupts::x2apic,
    memory::{frame_allocator::alloc_frame, paging::get_page_flags, HHDM_OFFSET},
    processes::process::{
        run_process_ring3, ProcessState, UnsafePCB, NEXT_PID, PCB, PROCESS_TABLE,
    },
    serial_println,
};

/// Creates a new child process, Copy-on-write
pub fn sys_fork() -> u64 {
    let child_pid = NEXT_PID.fetch_add(1, Ordering::SeqCst);
    let cpuid: u32 = x2apic::current_core_id() as u32;
    let parent_pid = current_running_event_info(cpuid).pid;

    let process = {
        // clone the arc - the first reference is dropped out of this scope and we use the cloned one
        let process_table = PROCESS_TABLE.read();
        process_table
            .get(&parent_pid)
            .expect("can't find pcb in process table")
            .clone()
    };

    let parent_pcb = process.pcb.get();

    let child_pcb = Arc::new(UnsafePCB::new(unsafe { (*parent_pcb).clone() }));
    unsafe {
        (*child_pcb.pcb.get()).registers.rax = 0;
        (*child_pcb.pcb.get()).registers.rip = (*parent_pcb).registers.rip + 8;
        serial_println!("PARENT PCB RIP: {:#X}", (*parent_pcb).registers.rip);
        (*child_pcb.pcb.get()).state = ProcessState::Ready;
    }

    let mut mapper = unsafe { (*parent_pcb).create_mapper() };
    let child_pml4_frame =
        duplicate_page_table_recursive(unsafe { (*parent_pcb).pml4_frame }, 4);
    unsafe { (*child_pcb.pcb.get()).pml4_frame = child_pml4_frame };

    {
        PROCESS_TABLE.write().insert(child_pid, child_pcb);
    }

    schedule_process(cpuid, unsafe { run_process_ring3(child_pid) }, child_pid);

    return child_pid as u64;
}


/// Recursively duplicate a page table.
///
/// # Arguments
/// * parent_frame - reference to parent page tables
/// * level - 4 for PML4, 3 for PDPT, 2 for PD, and 1 for PT
/// * mapper - new mapper
///
/// # Return
/// Returns a PhysFrame that represents the new pml4 frame for child
fn duplicate_page_table_recursive(
    parent_frame: PhysFrame,
    level: u8,
) -> PhysFrame {
    // Allocate a new frame for this level’s table.
    let child_frame = alloc_frame().expect("Frame allocation failed");
    // Map it into our address space using HHDM_OFFSET.
    let child_table_ptr =
        (HHDM_OFFSET.as_u64() + child_frame.start_address().as_u64()) as *mut PageTable;

    unsafe { (*child_table_ptr).zero() };

    // Obtain a pointer to the parent table.
    let parent_table_ptr =
        (HHDM_OFFSET.as_u64() + parent_frame.start_address().as_u64()) as *mut PageTable;

    let parent_table = unsafe { &mut *parent_table_ptr };
    let child_table: &mut PageTable = unsafe { &mut *child_table_ptr };
    // Iterate over all 512 entries.
    for (i, parent_entry) in parent_table.iter_mut().enumerate() {
        if parent_entry.is_unused() {
            continue;
        }
    
        // Copy over kernel mappings
        if level == 4 && i >= 256 {
            child_table[i].set_addr(parent_entry.addr(), parent_entry.flags());
            continue;
        }

        if level > 1 {
            let new_child_lower_frame = duplicate_page_table_recursive(
                PhysFrame::containing_address(parent_entry.addr()),
                level - 1);
            child_table[i].set_addr(new_child_lower_frame.start_address(), parent_entry.flags());
        } else {
            let mut flags = parent_entry.flags();
            // Mark as COW if originally writable
            if flags.contains(PageTableFlags::PRESENT) {
                if flags.contains(PageTableFlags::WRITABLE) {
                    flags.set(PageTableFlags::BIT_9, true);
                    flags.set(PageTableFlags::WRITABLE, false);
                }
                parent_entry.set_addr(parent_entry.addr(), flags);

                child_table[i].set_addr(parent_entry.addr(), flags);
            }
        }
    }

    child_frame
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::processes::process::PCB;

    fn verify_page_table_walk(parent_pcb: &mut PCB, child_pcb: &mut PCB) {
        assert_eq!(
            (*parent_pcb).pml4_frame.start_address(),
            (*child_pcb).pml4_frame.start_address()
        );
        let mut parent_mapper = unsafe { parent_pcb.create_mapper() };
        let mut child_mapper = unsafe { child_pcb.create_mapper() };

        for i in 0..512 {
            let parent_entry = &parent_mapper.level_4_table()[i];
            let child_entry = &child_mapper.level_4_table()[i];
            if parent_entry.is_unused() {
                assert!(child_entry.is_unused());
            } else {
                assert!(parent_entry.flags().contains(PageTableFlags::BIT_9));
                assert!(!parent_entry.flags().contains(PageTableFlags::WRITABLE));
                assert_eq!(parent_entry.flags(), child_entry.flags());
                assert_eq!(parent_entry.addr(), child_entry.addr());
                assert_eq!(
                    parent_entry
                        .frame()
                        .expect("Could not retrieve parent frame"),
                    child_entry.frame().expect("Could not retrieve child frame")
                );
                let parent_pdpt_frame = PhysFrame::containing_address(parent_entry.addr());
                let child_pdpt_frame = PhysFrame::containing_address(child_entry.addr());
                recursive_walk(
                    parent_pdpt_frame,
                    child_pdpt_frame,
                    3,
                    &mut parent_mapper,
                    &mut child_mapper,
                );
            }
        }
    }

    fn recursive_walk(
        parent_frame: PhysFrame,
        child_frame: PhysFrame,
        level: u8,
        parent_mapper: &mut OffsetPageTable,
        child_mapper: &mut OffsetPageTable,
    ) {
        let parent_virt = HHDM_OFFSET.as_u64() + parent_frame.start_address().as_u64();
        let child_virt = HHDM_OFFSET.as_u64() + child_frame.start_address().as_u64();
        // make sure the child and parent frame virtual addresses are the same
        assert_eq!(parent_virt, child_virt);

        let parent_table = unsafe { &mut *(parent_virt as *mut PageTable) };
        let child_table = unsafe { &mut *(parent_virt as *mut PageTable) };

        for i in 0..512 {
            let parent_entry = &parent_table[i];
            let child_entry = &child_table[i];

            // from the parent and child tables, ensure each entry is the same
            assert_eq!(parent_entry.flags(), child_entry.flags());
            assert_eq!(parent_entry.addr(), child_entry.addr());
            assert!(parent_entry.flags().contains(PageTableFlags::BIT_9));
            assert!(!parent_entry.flags().contains(PageTableFlags::WRITABLE));
            assert_eq!(
                parent_entry
                    .frame()
                    .expect("Could not retrieve parent frame"),
                child_entry.frame().expect("Could not retrieve child frame")
            );

            if level > 1 {
                let parent_frame: PhysFrame = PhysFrame::containing_address(parent_entry.addr());
                let child_frame: PhysFrame = PhysFrame::containing_address(child_entry.addr());
                recursive_walk(
                    parent_frame,
                    child_frame,
                    level - 1,
                    parent_mapper,
                    child_mapper,
                );
            }
        }
    }

    #[test_case]
    fn test_simple_fork() {
        use crate::{
            constants::processes::FORK_SIMPLE,
            events::schedule_process,
            processes::process::{create_process, print_process_table, run_process_ring3},
        };

        let parent_pid = create_process(FORK_SIMPLE);
        let cpuid: u32 = x2apic::current_core_id() as u32;
        schedule_process(cpuid, unsafe { run_process_ring3(parent_pid) }, parent_pid);
        for i in 0..1000000000_u64 {}
        let child_pid = parent_pid + 1;

        serial_println!("PARENT PID {}", parent_pid);

        // since no other processes are running or being created we assume that
        // the child pid is one more than the child pid
        let process_table = PROCESS_TABLE.read();
        // unsafe {
        //     print_process_table(&PROCESS_TABLE);
        // }
        assert!(
            process_table.contains_key(&child_pid),
            "Child process not found in table"
        );

        let parent_pcb = process_table
            .get(&parent_pid)
            .expect("Could not get parent pcb from process table")
            .pcb
            .get();
        let child_pcb = process_table
            .get(&child_pid)
            .expect("Could not get child pcb from process table")
            .pcb
            .get();

        // check that some of the fields are equivalent
        unsafe {
            assert_eq!((*parent_pcb).fd_table, (*child_pcb).fd_table);
            assert_eq!((*parent_pcb).kernel_rip, (*child_pcb).kernel_rip);
            assert_eq!((*parent_pcb).kernel_rsp, (*child_pcb).kernel_rsp);
            assert_eq!((*parent_pcb).registers, (*child_pcb).registers);
        }

        // check that the pml4 frame is set correctly
        unsafe {
            verify_page_table_walk(&mut *parent_pcb, &mut *child_pcb);
        }
    }
}
