//! - Interrupt Descriptor Table (IDT) setup
//!
//! This module provides:
//! - Interrupt Descriptor Table (IDT) setup
//! - Exception handlers (breakpoint, page fault, double fault, etc.)
//! - Timer interrupt handling
//! - Functions to enable/disable interrupts

use lazy_static::lazy_static;
use x86_64::{
    instructions::interrupts,
    structures::{
        idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
        paging::{OffsetPageTable, Page, PageTable},
    },
    VirtAddr,
};

use crate::{
    constants::idt::{SYSCALL_HANDLER, TIMER_VECTOR, TLB_SHOOTDOWN_VECTOR},
    events::{current_running_event_info, schedule_process, EventInfo},
    interrupts::x2apic::{self, current_core_id, TLB_SHOOTDOWN_ADDR},
    memory::{paging::create_mapping, HHDM_OFFSET},
    prelude::*,
    processes::process::{run_process_ring3, ProcessState, PROCESS_TABLE},
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
            .set_handler_fn(syscall_handler)
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
        "EXCEPTION: PAGE FAULT\nFaulting Address: {:?}\nError Code: {:X}\n{:#?}",
        faulting_address,
        error_code,
        stack_frame
    );

    let page = Page::containing_address(VirtAddr::new(faulting_address));

    // check for stack growth
    if stack_pointer - 64 <= faulting_address && faulting_address < (*HHDM_OFFSET).as_u64() {
        create_mapping(page, &mut mapper, None);
    }

    panic!("PAGE FAULT!");
}

#[no_mangle]
extern "x86-interrupt" fn syscall_handler(_: InterruptStackFrame) {
    unsafe {
        // I believe we need to save registers
        core::arch::asm!("push rax", "call dispatch_syscall", "pop rax",);
    }

    x2apic::send_eoi();
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
    let cpuid: u32 = x2apic::current_core_id() as u32;
    let event: EventInfo = current_running_event_info(cpuid);
    if event.pid == 0 {
        x2apic::send_eoi();
        return;
    }

    // Get PCB from PID
    let preemption_info = unsafe {
        let mut process_table = PROCESS_TABLE.write();
        let process = process_table
            .get_mut(&event.pid)
            .expect("Process not found");

        let pcb = process.pcb.get();

        if (*pcb).state != ProcessState::Running {
            x2apic::send_eoi();
            return;
        }

        // save registers to the PCB
        let stack_ptr: *const u64 = rsp as *const u64;

        (*pcb).registers.rax = *stack_ptr.add(0);
        (*pcb).registers.rbx = *stack_ptr.add(1);
        (*pcb).registers.rcx = *stack_ptr.add(2);
        (*pcb).registers.rdx = *stack_ptr.add(3);
        (*pcb).registers.rsi = *stack_ptr.add(4);
        (*pcb).registers.rdi = *stack_ptr.add(5);
        (*pcb).registers.r8 = *stack_ptr.add(6);
        (*pcb).registers.r9 = *stack_ptr.add(7);
        (*pcb).registers.r10 = *stack_ptr.add(8);
        (*pcb).registers.r11 = *stack_ptr.add(9);
        (*pcb).registers.r12 = *stack_ptr.add(10);
        (*pcb).registers.r13 = *stack_ptr.add(11);
        (*pcb).registers.r14 = *stack_ptr.add(12);
        (*pcb).registers.r15 = *stack_ptr.add(13);
        (*pcb).registers.rbp = *stack_ptr.add(14);
        // saved from interrupt stack frame
        (*pcb).registers.rsp = *stack_ptr.add(18);
        (*pcb).registers.rip = *stack_ptr.add(15);
        (*pcb).registers.rflags = *stack_ptr.add(17);

        (*pcb).state = ProcessState::Blocked;

        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

    unsafe {
        schedule_process(cpuid, run_process_ring3(event.pid), event.pid);

        // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
        core::arch::asm!(
            "mov rsp, {0}",
            "push {1}",
            in(reg) preemption_info.0,
            in(reg) preemption_info.1
        );

        x2apic::send_eoi();

        core::arch::asm!("ret");
    }
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
