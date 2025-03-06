//! - Interrupt Descriptor Table (IDT) setup
//!
//! This module provides:
//! - Interrupt Descriptor Table (IDT) setup
//! - Exception handlers (breakpoint, page fault, double fault, etc.)
//! - Timer interrupt handling
//! - Functions to enable/disable interrupts

use core::{arch::naked_asm, ptr};

use alloc::sync::Arc;
use lazy_static::lazy_static;
use x86_64::{
    instructions::interrupts,
    structures::{
        idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
        paging::{
            mapper::PageTableFrameMapping, OffsetPageTable, Page, PageTable, PageTableFlags,
            Translate,
        },
    },
    VirtAddr,
};

use crate::{
    constants::{
        idt::{SYSCALL_HANDLER, TIMER_VECTOR, TLB_SHOOTDOWN_VECTOR},
        memory::PAGE_SIZE,
        syscalls::{SYSCALL_EXIT, SYSCALL_FORK, SYSCALL_MMAP, SYSCALL_NANOSLEEP, SYSCALL_PRINT},
    },
    events::inc_runner_clock,
    interrupts::x2apic::{self, current_core_id, TLB_SHOOTDOWN_ADDR},
    memory::{
        frame_allocator::alloc_frame,
        mm::{AnonVmArea, AnonVmaChain},
        paging::{create_mapping, create_mapping_to_frame, get_page_flags, update_mapping},
        HHDM_OFFSET,
    },
    prelude::*,
    processes::process::{get_current_pid, preempt_process, PROCESS_TABLE},
    syscalls::{
        fork::sys_fork,
        mmap::sys_mmap,
        syscall_handlers::{sys_exit, sys_nanosleep, sys_print},
    },
};

lazy_static! {
    /// The system's Interrupt Descriptor Table.
    /// Contains handlers for:
    /// - CPU exceptions (breakpoint, page fault, double fault)
    /// - Timer interrupts
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(0);
        }
        idt[TIMER_VECTOR].set_handler_fn(naked_timer_handler);
        idt[SYSCALL_HANDLER]
            .set_handler_fn(naked_syscall_handler)
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
        idt[TLB_SHOOTDOWN_VECTOR].set_handler_fn(tlb_shootdown_handler);
        idt
    };
}

/// Loads the IDT for the specified CPU core.
pub fn init_idt(_cpu_id: u32) {
    IDT.load();
}

/// Enables interrupts on the current CPU.
pub fn enable() {
    interrupts::enable();
}

/// Disables interrupts on the current CPU.
pub fn disable() {
    interrupts::disable();
}

/// Executes a closure with interrupts disabled.
///
/// # Arguments
/// * `f` - The closure to execute
///
/// # Returns
/// Returns the result of the closure
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    interrupts::without_interrupts(f)
}

/// Checks if interrupts are enabled on the current CPU.
pub fn are_enabled() -> bool {
    interrupts::are_enabled()
}

/// Executes a closure with interrupts enabled, restoring the previous interrupt state after.
///
/// # Arguments
/// * `f` - The closure to execute
///
/// # Returns
/// Returns the result of the closure
pub fn with_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let initially_enabled = are_enabled();
    if !initially_enabled {
        enable();
    }

    let result = f();

    if !initially_enabled {
        disable();
    }

    result
}

/// Handles breakpoint exceptions by printing debug information.
extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

/// Handles double fault exceptions by panicking with debug information.
extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

/// Handles page fault exceptions by printing fault information.
extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    serial_println!("current core is {}", x2apic::current_core_id());
    use x86_64::registers::control::{Cr2, Cr3};

    let faulting_address = Cr2::read().expect("Cannot read faulting address").as_u64();
    let pml4 = Cr3::read().0;
    let new_pml4_phys = pml4.start_address();
    let new_pml4_virt = VirtAddr::new((*HHDM_OFFSET).as_u64()) + new_pml4_phys.as_u64();
    let new_pml4_ptr: *mut PageTable = new_pml4_virt.as_mut_ptr();

    let mut mapper =
        unsafe { OffsetPageTable::new(&mut *new_pml4_ptr, VirtAddr::new((*HHDM_OFFSET).as_u64())) };
    let stack_pointer = stack_frame.stack_pointer.as_u64();

    serial_println!(
        "EXCEPTION: PAGE FAULT\nFaulting Address: {:#X}\nError Code: {:X}\n{:#?}",
        faulting_address,
        error_code,
        stack_frame
    );

    let page = Page::containing_address(VirtAddr::new(faulting_address));

    let process = {
        let process_table = PROCESS_TABLE.read();
        process_table
            .get(&get_current_pid())
            .expect("Cannot find current pid")
            .clone()
    };

    let vma = unsafe {
        (*process.pcb.get())
            .mm
            .find_vma(faulting_address)
            .expect("Vma not found?")
    };
    let fault_round_down: u64 = (faulting_address) & !(PAGE_SIZE as u64 - 1);
    let backing = Arc::clone(&(vma.backing));
    unsafe {
        let frame = backing.find_mapping(&vma, fault_round_down);
        if frame.is_some() {
            create_mapping_to_frame(
                page,
                &mut mapper,
                Some(
                    PageTableFlags::WRITABLE
                        | PageTableFlags::USER_ACCESSIBLE
                        | PageTableFlags::PRESENT,
                ),
                *frame.unwrap().frame,
            );
        } else {
            let new_frame = create_mapping(
                page,
                &mut mapper,
                Some(
                    PageTableFlags::WRITABLE
                        | PageTableFlags::USER_ACCESSIBLE
                        | PageTableFlags::PRESENT,
                ),
            );

            backing.insert_mapping(Arc::new(AnonVmaChain {
                vma,
                offset: page.start_address().as_u64(),
                frame: Arc::new(new_frame),
            }));
        }
    }

    return;
    unreachable!("Testing stack");
    // testing only above for stack access, worrying about the rest later
    // -----------------------------------------------------------------------------------

    let frame = mapper.translate_addr(VirtAddr::new(faulting_address));
    serial_println!("Frame mapped to this VA is {:#?}", frame);
    let mut flags: PageTableFlags =
        get_page_flags(page, &mut mapper).expect("Could not get page flags");

    let cow = flags.contains(PageTableFlags::BIT_9);
    let present = flags.contains(PageTableFlags::PRESENT);
    let read_only = !flags.contains(PageTableFlags::WRITABLE);

    let caused_by_write = (error_code.bits() & PageFaultErrorCode::CAUSED_BY_WRITE.bits()) != 0;

    // If error code was caused by write and permissions of PTE are for COW
    if cow && caused_by_write && read_only && present {
        // before we update mapping, we save data
        serial_println!("In page fault handler for COW");
        let start = page.start_address();
        let src_ptr = start.as_mut_ptr();

        let mut buffer: [u8; PAGE_SIZE] = [0; PAGE_SIZE];

        unsafe {
            ptr::copy_nonoverlapping(src_ptr, buffer.as_mut_ptr(), PAGE_SIZE);
        }

        flags.set(PageTableFlags::BIT_9, false);
        flags.set(PageTableFlags::WRITABLE, true);

        let frame = alloc_frame().expect("Allocation failed");
        update_mapping(page, &mut mapper, frame, Some(flags));
        unsafe {
            ptr::copy_nonoverlapping(buffer.as_mut_ptr(), src_ptr, PAGE_SIZE);
        }
        return;
    }

    // check for stack growth
    if stack_pointer - 64 <= faulting_address && faulting_address < (*HHDM_OFFSET).as_u64() {
        create_mapping(page, &mut mapper, None);
        return;
    }

    // check if lazy loaded address from mmap
    let pid = get_current_pid();
    let process_table = PROCESS_TABLE.write();
    let process = process_table
        .get(&pid)
        .expect("Could not get pcb from process table");
    let pcb = unsafe { &mut *process.pcb.get() };
    let mmaps = &mut pcb.mmaps;

    for entry in mmaps.iter_mut() {
        if entry.contains(faulting_address) {
            serial_println!("Entry start: {}", entry.start);
            let index = ((faulting_address - entry.start) / PAGE_SIZE as u64) as usize;
            let frame = alloc_frame().expect("Could not allocate frame");

            entry.loaded[index] = true;
            update_mapping(
                page,
                &mut mapper,
                frame,
                Some(
                    PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::USER_ACCESSIBLE,
                ),
            );

            if !entry.loaded[index] && entry.fd == -1 {
                break;
            } else if !entry.loaded[index] && entry.fd != -1 {
                let _open_file = pcb.fd_table[entry.fd as usize];
                let _pos = faulting_address - entry.start + entry.offset;
                // figure out where in the file we are
                // load file content
                // write content to physmem
            }
        }
        break;
    }
}
#[no_mangle]
#[naked]
pub extern "x86-interrupt" fn naked_syscall_handler(_: InterruptStackFrame) {
    unsafe {
        naked_asm!(
            // Push registers to save them
            "push r11",
            "push rax",
            "push rbx",
            "push rcx",
            "push rdx",
            "push rsi",
            "push rdi",
            "push rbp",
            "mov rdi, rsp",
            // Call the syscall_handler
            "call syscall_handler",
            // Restore registers
            "mov r11, rax",
            "pop rbp",
            "pop rdi",
            "pop rsi",
            "pop rdx",
            "pop rcx",
            "pop rbx",
            "pop rax",
            "mov rax, r11",
            "pop r11",
            "iretq"
        );
    }
}

#[no_mangle]
fn syscall_handler(rsp: u64) {
    let syscall_num: u32;
    let p1: u64;
    let p2: u64;
    let p3: u64;
    let p4: u64;
    let p5: u64;
    let p6: u64;
    let stack_ptr: *const u64 = rsp as *const u64;
    unsafe {
        syscall_num = *stack_ptr.add(6) as u32;
        p1 = *stack_ptr.add(5);
        p2 = *stack_ptr.add(4);
        p3 = *stack_ptr.add(3);
        p4 = *stack_ptr.add(2);
        p5 = *stack_ptr.add(1);
        p6 = *stack_ptr.add(0);
    }

    x2apic::send_eoi();

    if syscall_num == SYSCALL_EXIT {
        sys_exit(p1 as i64);
    } else if syscall_num == SYSCALL_MMAP {
        let val = sys_mmap(p1, p2, p3, p4, p5 as i64, p6).expect("Mmap failed");
        unsafe {
            core::arch::asm!(
                "mov rax, {0}",
                in (reg) val,
            )
        }
    } else if syscall_num == SYSCALL_PRINT {
        let val = sys_print(p1 as *const u8);
        unsafe {
            core::arch::asm!(
                "mov rax, {0}",
                in (reg) val,
            )
        }
    }
    // } else if syscall_num == SYSCALL_FORK {
    //     let val = sys_fork();
    //     unsafe {
    //         core::arch::asm!(
    //             "mov rax, {0}",
    //             in (reg) val,
    //         )
    //     }
    // }
}

#[naked]
#[allow(undefined_naked_function_abi)]
extern "x86-interrupt" fn naked_timer_handler(_: InterruptStackFrame) {
    unsafe {
        core::arch::naked_asm!(
            "
            push rbp
            push r15
            push r14
            push r13
            push r12
            push r11
            push r10
            push r9
            push r8
            push rdi
            push rsi
            push rdx
            push rcx
            push rbx
            push rax

            cld
            mov	rdi, rsp
            call timer_handler

            pop rax
            pop rbx
            pop rcx
            pop rdx
            pop rsi
            pop rdi
            pop r8
            pop r9
            pop r10
            pop r11
            pop r12
            pop r13
            pop r14
            pop r15
            pop rbp
            iretq
      "
        );
    }
}

#[no_mangle]
extern "C" fn timer_handler(rsp: u64) {
    inc_runner_clock();

    preempt_process(rsp);
    x2apic::send_eoi();
}

// TODO Technically, this design means that when TLB Shootdows happen, each core must sequentially
// invalidate its TLB rather than doing this in parallel. While this is slow, this is of low
// priority to fix
extern "x86-interrupt" fn tlb_shootdown_handler(_: InterruptStackFrame) {
    let core = current_core_id();
    {
        let mut addresses = TLB_SHOOTDOWN_ADDR.lock();
        let vaddr_to_invalidate = addresses[core];
        if vaddr_to_invalidate != 0 {
            unsafe {
                core::arch::asm!("invlpg [{}]", in (reg) vaddr_to_invalidate, options(nostack, preserves_flags));
            }
            addresses[core] = 0;
        }
    }
    x2apic::send_eoi();
}
