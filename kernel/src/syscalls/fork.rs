use core::sync::atomic::Ordering;

use alloc::sync::Arc;
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame};

use crate::{
    events::{current_running_event_info, schedule_process_on},
    memory::{
        frame_allocator::{alloc_frame, with_buddy_frame_allocator},
        mm::Mm,
        HHDM_OFFSET,
    },
    processes::{
        process::{ProcessState, UnsafePCB, NEXT_PID, PROCESS_TABLE},
        registers::ForkingRegisters,
    },
};

/// Create an exact clone of a process to create a child process.
///
/// # Arguments
/// * `reg_vals' - Register values of parent process at time of
///   parent process calling 'syscall' - r11 stores
///   rflags and rcx stores next rip.
///
/// # Return
/// Returns child pid
pub fn sys_fork(reg_vals: &ForkingRegisters) -> u64 {
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

    // Use the register values captured at syscall to populate register values of child PCB.
    // This follows 64-bit syscall conventions of where values are stored and which reg vals are maintained.
    let child_pcb = Arc::new(UnsafePCB::new(unsafe { (*parent_pcb).clone() }));
    unsafe {
        (*child_pcb.pcb.get()).registers.rax = 0;
        (*child_pcb.pcb.get()).registers.rbx = reg_vals.rbx;
        (*child_pcb.pcb.get()).registers.rcx = reg_vals.rcx;
        (*child_pcb.pcb.get()).registers.rdx = reg_vals.rdx;
        (*child_pcb.pcb.get()).registers.rsi = reg_vals.rsi;
        (*child_pcb.pcb.get()).registers.rdi = reg_vals.rdi;
        (*child_pcb.pcb.get()).registers.r8 = reg_vals.r8;
        (*child_pcb.pcb.get()).registers.r9 = reg_vals.r9;
        (*child_pcb.pcb.get()).registers.r10 = reg_vals.r10;
        (*child_pcb.pcb.get()).registers.r11 = reg_vals.r11;
        (*child_pcb.pcb.get()).registers.r12 = reg_vals.r12;
        (*child_pcb.pcb.get()).registers.r13 = reg_vals.r13;
        (*child_pcb.pcb.get()).registers.r14 = reg_vals.r14;
        (*child_pcb.pcb.get()).registers.r15 = reg_vals.r15;
        (*child_pcb.pcb.get()).registers.rbp = reg_vals.rbp;
        // By syscall instruction semantics, rcx will store next instruction to be ran.
        (*child_pcb.pcb.get()).registers.rip = reg_vals.rcx;
        (*child_pcb.pcb.get()).registers.rflags = reg_vals.r11;
        (*child_pcb.pcb.get()).registers.rsp = reg_vals.rsp;
        (*child_pcb.pcb.get()).state = ProcessState::Ready;
    }

    // duplicate page table for child - intermediate layers are real clones, final-level frames are COW
    let child_pml4_frame =
        duplicate_page_table_recursive(unsafe { (*parent_pcb).mm.pml4_frame }, 4);

    // TODO: go through this logic and ensure that both parent and child VMAs are set to COW
    unsafe {
        (*parent_pcb).mm.with_vma_tree_mutable(|tree| {
            for vma_entry in tree.iter_mut() {
                let vma_lock = vma_entry.1.lock();
                let start = vma_lock.start;
                let end = vma_lock.end;
                let segments = vma_lock.segments.clone();
                let flags = vma_lock.flags;
                drop(vma_lock);

                // Use the extracted data when inserting into the child tree.
                (*child_pcb.pcb.get())
                    .mm
                    .with_vma_tree_mutable(|child_tree| {
                        Mm::insert_copied_vma(child_tree, start, end, segments.clone(), flags);
                    });
            }
        })
    }

    unsafe { (*child_pcb.pcb.get()).mm.pml4_frame = child_pml4_frame };
    {
        PROCESS_TABLE.write().insert(child_pid, child_pcb);
    }

    schedule_process_on(1, child_pid);

    child_pid as u64
}

/// Recursively duplicate a page table.
///
/// # Arguments
/// * `parent_frame` - reference to parent page tables
/// * `level` - 4 for PML4, 3 for PDPT, 2 for PD, and 1 for PT
/// * `mapper` - new mapper
///
/// # Return
/// Returns a PhysFrame that represents the new pml4 frame for child
fn duplicate_page_table_recursive(parent_frame: PhysFrame, level: u8) -> PhysFrame {
    // Allocate a new frame for this level’s table.
    let child_frame = alloc_frame().expect("Frame allocation failed");
    // Map it into our address space using HHDM_OFFSET.
    let child_table_ptr =
        (HHDM_OFFSET.as_u64() + child_frame.start_address().as_u64()) as *mut PageTable;

    unsafe { (*child_table_ptr).zero() };

    // Obtain a mutable pointer to the parent table.
    let parent_table_ptr =
        (HHDM_OFFSET.as_u64() + parent_frame.start_address().as_u64()) as *mut PageTable;

    // Convert to mutable references so we can update parent's entries.
    let parent_table = unsafe { &mut *parent_table_ptr };
    let child_table = unsafe { &mut *child_table_ptr };

    // Iterate over all 512 entries.
    for (i, parent_entry) in parent_table.iter_mut().enumerate() {
        if parent_entry.is_unused() {
            continue;
        }

        // For the PML4 level, share kernel mappings.
        if level == 4 && i >= 256 {
            // For kernel space, simply copy the parent's entry.
            child_table[i].set_addr(parent_entry.addr(), parent_entry.flags());
            continue;
        }

        if level > 1 {
            // For intermediate tables, recursively duplicate the lower-level table.
            let new_child_lower_frame = duplicate_page_table_recursive(
                PhysFrame::containing_address(parent_entry.addr()),
                level - 1,
            );
            child_table[i].set_addr(new_child_lower_frame.start_address(), parent_entry.flags());
        } else {
            // For leaf entries, if the page is writable mark it as copy-on-write.
            let mut flags = parent_entry.flags();
            if flags.contains(PageTableFlags::PRESENT) {
                if flags.contains(PageTableFlags::WRITABLE) {
                    // Mark this entry as copy-on-write:
                    flags.set(PageTableFlags::WRITABLE, false);
                    // Also update the parent's entry with the new flags.
                    parent_entry.set_addr(parent_entry.addr(), flags);
                }
                // Set the child's entry to the (possibly updated) flags.
                child_table[i].set_addr(parent_entry.addr(), flags);

                with_buddy_frame_allocator(|alloc| {
                    alloc.inc_ref_count(PhysFrame::containing_address(parent_entry.addr()));
                });
            }
        }
    }

    child_frame
}

#[cfg(test)]
mod tests {
    use x86_64::structures::paging::{
        OffsetPageTable, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    };

    use crate::{
        constants::processes::FORK_SIMPLE,
        events::{
            current_running_event, futures::await_on::AwaitProcess, get_runner_time,
            schedule_process,
        },
        memory::HHDM_OFFSET,
        processes::{process::create_process, registers::ForkingRegisters},
        syscalls::syscall_handlers::{EXIT_CODES, PML4_FRAMES, REGISTER_VALUES},
    };

    fn verify_page_table_walk(parent_pml4: PhysFrame<Size4KiB>, child_pml4: PhysFrame<Size4KiB>) {
        let parent_mapper = unsafe {
            let virt = *HHDM_OFFSET + parent_pml4.start_address().as_u64();
            let ptr = virt.as_mut_ptr::<PageTable>();
            OffsetPageTable::new(&mut *ptr, *HHDM_OFFSET)
        };
        let child_mapper = unsafe {
            let virt = *HHDM_OFFSET + child_pml4.start_address().as_u64();
            let ptr = virt.as_mut_ptr::<PageTable>();
            OffsetPageTable::new(&mut *ptr, *HHDM_OFFSET)
        };

        for i in 0..256 {
            let parent_entry = &parent_mapper.level_4_table()[i];
            let child_entry = &child_mapper.level_4_table()[i];
            if parent_entry.is_unused() {
                assert!(child_entry.is_unused());
                continue;
            } else {
                assert_eq!(parent_entry.flags(), child_entry.flags());
                let parent_pdpt_frame = PhysFrame::containing_address(parent_entry.addr());
                recursive_walk(parent_pdpt_frame, 3);
            }
        }
    }

    fn recursive_walk(parent_frame: PhysFrame, level: u8) {
        let parent_virt = HHDM_OFFSET.as_u64() + parent_frame.start_address().as_u64();

        let parent_table = unsafe { &mut *(parent_virt as *mut PageTable) };
        let child_table = unsafe { &mut *(parent_virt as *mut PageTable) };

        for i in 0..512 {
            let parent_entry = &parent_table[i];
            let child_entry = &child_table[i];
            if parent_entry.is_unused() {
                assert!(child_entry.is_unused());
                continue;
            }

            // from the parent and child tables, ensure each entry is the same
            assert_eq!(parent_entry.flags(), child_entry.flags());
            if level == 1 {
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
                recursive_walk(parent_frame, level - 1);
            }
        }
    }

    #[test_case]
    async fn test_simple_fork() {
        let parent_pid = create_process(FORK_SIMPLE);
        schedule_process(parent_pid);
        let _waiter = AwaitProcess::new(
            parent_pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        )
        .await;
        let child_pid = parent_pid + 1;

        let _waiter = AwaitProcess::new(
            parent_pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        )
        .await;

        let _waiter = AwaitProcess::new(
            child_pid,
            get_runner_time(3_000_000_000),
            current_running_event().unwrap(),
        )
        .await;

        let exit_codes = EXIT_CODES.lock();
        let parent_exit_code = exit_codes
            .get(&parent_pid)
            .expect("Could not find parent pid.");
        let child_exit_code = exit_codes
            .get(&child_pid)
            .expect("Could not find child pid.");

        let registers = REGISTER_VALUES.lock();

        let (parent_regs_ptr, child_regs_ptr) = {
            let parent = registers
                .get(&parent_pid)
                .expect("Could not find parent pid.")
                as *const ForkingRegisters;
            let child = registers
                .get(&child_pid)
                .expect("Could not find child pid.")
                as *const ForkingRegisters;
            (parent, child)
        };

        let parent_regs: &mut ForkingRegisters = unsafe { &mut *(parent_regs_ptr as *mut _) };
        let child_regs: &mut ForkingRegisters = unsafe { &mut *(child_regs_ptr as *mut _) };

        let frames = PML4_FRAMES.lock();
        let parent_pml4 = frames.get(&parent_pid).expect("Could not find parent pid.");
        let child_pml4 = frames.get(&child_pid).expect("Could not find child pid.");

        assert_eq!(parent_exit_code, child_exit_code);
        assert_eq!(child_pid as u64, parent_regs.r12);
        child_regs.r12 = child_pid as u64;
        assert_eq!(parent_regs, child_regs);

        // check that the pml4 frame is set correctly
        verify_page_table_walk(*parent_pml4, *child_pml4);
    }
}
