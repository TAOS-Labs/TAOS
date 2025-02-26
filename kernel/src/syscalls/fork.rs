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
        (*child_pcb.pcb.get()).state = ProcessState::Ready;
    }

    set_page_table_cow(unsafe { &mut *child_pcb.pcb.get() }, unsafe {
        &mut *parent_pcb
    });

    {
        PROCESS_TABLE.write().insert(child_pid, child_pcb);
    }

    schedule_process(cpuid, unsafe { run_process_ring3(child_pid) }, child_pid);

    return child_pid as u64;
}

fn set_page_table_cow(child_pcb: &mut PCB, parent_pcb: &mut PCB) {
    let mut child_mapper = unsafe { child_pcb.create_mapper() };
    let mut parent_mapper = unsafe { parent_pcb.create_mapper() };

    for i in 0..256 {
        let entry = &parent_mapper.level_4_table()[i];
        if entry.is_unused() {
            continue;
        }
        let pdpt_frame = PhysFrame::containing_address(entry.addr());
        // set as copy on write
        unsafe { set_page_table_cow_helper(pdpt_frame, 3, &mut child_mapper, &mut parent_mapper) };
    }
}

unsafe fn set_page_table_cow_helper(
    parent_frame: PhysFrame,
    level: u8,
    child_mapper: &mut OffsetPageTable,
    parent_mapper: &mut OffsetPageTable,
) {
    let parent_va = HHDM_OFFSET.as_u64() + parent_frame.start_address().as_u64();
    let parent_table = unsafe { &mut *(parent_va as *mut PageTable) };

    // At intermediate level - need to populate intermediate frame with lower levels it points to
    if level > 1 {
        let child_intermediate_frame: PhysFrame = alloc_frame().expect("Failed to allocate frame.");
        let child_va = child_intermediate_frame.start_address().as_u64() + HHDM_OFFSET.as_u64();
        let child_table = unsafe { &mut *(child_va as *mut PageTable) };
        for (index, entry) in parent_table.iter_mut().enumerate() {
            child_table[index] = entry.clone();
            if entry.is_unused() {
                continue;
            }
            if (level == 1) {
                let mut page_flags = entry.flags();
                serial_println!("PAGE FLAGS BEFORE SETTING: {:#?}", page_flags);
                if page_flags.contains(PageTableFlags::PRESENT) {
                    if page_flags.contains(PageTableFlags::WRITABLE) {
                        page_flags.set(PageTableFlags::BIT_9, true);
                        page_flags.set(PageTableFlags::WRITABLE, false);
                    }
                    entry.set_flags(page_flags);
                    serial_println!("PAGE FLAGS AFTER SETTING: {:#?}", entry.flags());
                    serial_println!("FRAME ADDRESS: {:#?}", entry.addr());

                    child_table[index].set_flags(page_flags);
                }
            } else {
                set_page_table_cow_helper(
                    entry.frame().expect("Could not get frame from table"),
                    level - 1,
                    child_mapper,
                    parent_mapper,
                );
            }
        }
    }
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
