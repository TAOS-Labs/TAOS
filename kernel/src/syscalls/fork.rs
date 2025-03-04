use core::{ptr, sync::atomic::Ordering};

use alloc::sync::Arc;
use x86_64::structures::paging::{
    page_table::PageTableEntry, OffsetPageTable, PageTable, PageTableFlags, PhysFrame,
};

use crate::{
    events::{current_running_event_info, schedule_process, schedule_process_on},
    memory::{frame_allocator::{alloc_frame, with_buddy_frame_allocator}, HHDM_OFFSET},
    processes::{
        process::{ProcessState, UnsafePCB, NEXT_PID, PCB, PROCESS_TABLE},
        registers::NonFlagRegisters,
    },
    serial_println,
};

/// Creates a new child process, Copy-on-write
pub fn sys_fork() -> u64 {
    let child_pid = NEXT_PID.fetch_add(1, Ordering::SeqCst);
    let parent_pid = current_running_event_info().pid;

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
        (*child_pcb.pcb.get()).registers.rip = (*parent_pcb).registers.rip + 1;
        (*child_pcb.pcb.get()).state = ProcessState::Ready;
    }

    let child_pml4_frame = duplicate_page_table(unsafe { (*parent_pcb).pml4_frame }, 4);
    // verify_page_table_walk(unsafe { &mut *parent_pcb }, unsafe {
    //     &mut *child_pcb.pcb.get()
    // });
    unsafe { (*child_pcb.pcb.get()).pml4_frame = child_pml4_frame };

    {
        PROCESS_TABLE.write().insert(child_pid, child_pcb);
    }

    schedule_process_on(1, child_pid);

    child_pid as u64
}

/// Recursively duplicate a page table starting at the specified level.
///
/// # Arguments
/// * parent_frame - Physical frame of the parent page table
/// * level - Page table level (4 for PML4, 3 for PDPT, 2 for PD, 1 for PT)
///
/// # Returns
/// Newly allocated page table frame containing the duplicated structure
pub fn duplicate_page_table(parent_frame: PhysFrame, level: u8) -> PhysFrame {
    // Allocate and initialize new page table frame
    let child_frame = alloc_frame().expect("Failed to allocate frame");
    let child_table = get_table_mut(child_frame);
    child_table.zero();
    let parent_table = get_table_mut(parent_frame);

    // Process entries recursively
    duplicate_entries(parent_table, child_table, level);

    child_frame
}

/// Helper function to process entries recursively
fn duplicate_entries(parent: &mut PageTable, child: &mut PageTable, level: u8) {
    for (index, parent_entry) in parent.iter_mut().enumerate() {
        if parent_entry.is_unused() {
            continue;
        }

        // Preserve kernel mappings on higher half
        if level == 4 && index >= 256 {
            with_buddy_frame_allocator(|frc| {
                let frame = PhysFrame::from_start_address(parent_entry.addr())
                    .expect("Address not aligned");
                child[index].set_addr(parent_entry.addr(), parent_entry.flags());
                frc.inc_ref_count(frame);
            });
            continue;
        }

        match level {
            2..=4 => handle_upper_level(parent_entry, child, index, level),
            1 => handle_leaf_level(parent_entry, &mut child[index]),
            _ => unreachable!("Invalid page table level"),
        }
    }
}

/// Handle intermediate page table entries
fn handle_upper_level(
    parent_entry: &mut PageTableEntry,
    child_table: &mut PageTable,
    index: usize,
    level: u8,
) {
    let child_lower_frame = duplicate_page_table(
        PhysFrame::containing_address(parent_entry.addr()),
        level - 1,
    );
    child_table[index].set_addr(child_lower_frame.start_address(), parent_entry.flags());
}

/// Handle leaf page table entries
fn handle_leaf_level(parent_entry: &mut PageTableEntry, child_entry: &mut PageTableEntry) {
    let mut flags = parent_entry.flags();

    if flags.contains(PageTableFlags::PRESENT) {
        if flags.contains(PageTableFlags::WRITABLE) {
            flags.set(PageTableFlags::BIT_9, true); // COW flag
            flags.remove(PageTableFlags::WRITABLE);
        }
        parent_entry.set_flags(flags);

        with_buddy_frame_allocator(|frc| {
            let frame =
                PhysFrame::from_start_address(parent_entry.addr()).expect("Address not aligned");
            child_entry.set_addr(parent_entry.addr(), flags);
            frc.inc_ref_count(frame);
        });
    }
}

/// Helper to get mutable reference to a page table from a physical frame
fn get_table_mut(frame: PhysFrame) -> &'static mut PageTable {
    let phys_addr = frame.start_address();
    let virt_addr = HHDM_OFFSET.as_u64() + phys_addr.as_u64();
    unsafe { &mut *(virt_addr as *mut PageTable) }
}

fn verify_page_table_walk(parent_pcb: &mut PCB, child_pcb: &mut PCB) {
    assert_eq!(
        parent_pcb.pml4_frame.start_address(),
        child_pcb.pml4_frame.start_address()
    );
    let mut parent_mapper = unsafe { parent_pcb.create_mapper() };
    let mut child_mapper = unsafe { child_pcb.create_mapper() };

    for i in 0..256 {
        let parent_entry = &parent_mapper.level_4_table()[i];
        let child_entry = &child_mapper.level_4_table()[i];
        if parent_entry.is_unused() {
            assert!(child_entry.is_unused());
            continue;
        } else {
            assert_eq!(parent_entry.flags(), child_entry.flags());
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

    let parent_table = unsafe { &mut *(parent_virt as *mut PageTable) };
    let child_table = unsafe { &mut *(parent_virt as *mut PageTable) };

    for i in 0..512 {
        let parent_entry = &parent_table[i];
        let child_entry = &child_table[i];
        if (parent_entry.is_unused()) {
            assert!(child_entry.is_unused());
            continue;
        }

        // from the parent and child tables, ensure each entry is the same
        assert_eq!(parent_entry.flags(), child_entry.flags());
        if level == 1 {
            serial_println!(
                "Parent frame is {:#?}, Child frame is {:#?}",
                parent_entry.frame(),
                child_entry.frame()
            );
            // This logic is not correct and only works if you don't update the Writable flag during COW duplicate
            if parent_entry.flags().contains(PageTableFlags::WRITABLE) {
                assert!(parent_entry.flags().contains(PageTableFlags::BIT_9));
            }
            assert_eq!(parent_entry.addr(), child_entry.addr());
            assert_eq!(
                parent_entry.frame().expect("Could not find frame."),
                child_entry.frame().expect("Could not find frame.")
            );
        }
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

#[cfg(test)]
mod tests {
    use crate::{exit_qemu, QemuExitCode};

    use super::*;

    // #[test_case]
    fn test_simple_fork() {
        use crate::{
            constants::processes::FORK_SIMPLE, events::schedule_process,
            processes::process::create_process,
        };

        let parent_pid = create_process(FORK_SIMPLE);
        schedule_process(parent_pid);
        for _ in 0..100000000_u64 {}
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
