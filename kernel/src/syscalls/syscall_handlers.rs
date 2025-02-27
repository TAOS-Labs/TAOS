use core::{ffi::CStr, ptr::read_unaligned};

use x86_64::registers::{model_specific::{GsBase, KernelGsBase}, segmentation::{Segment64, GS}};

use crate::{
    constants::syscalls::*, events::{current_running_event_info, EventInfo}, interrupts::gdt::TSSS, processes::process::{clear_process_frames, sleep_process, ProcessState, PROCESS_TABLE}, serial_println, interrupts::x2apic::current_core_id
};

#[warn(unused)]
use crate::interrupts::x2apic;
#[allow(unused)]
use core::arch::naked_asm;

#[repr(C)]
#[derive(Debug)]
pub struct SyscallRegisters {
    pub number: u64, // syscall number (originally in rax)
    pub arg1: u64,   // originally in rdi
    pub arg2: u64,   // originally in rsi
    pub arg3: u64,   // originally in rdx
    pub arg4: u64,   // originally in r10
    pub arg5: u64,   // originally in r8
    pub arg6: u64,   // originally in r9
}

#[no_mangle]
fn get_ring_0_rsp() -> u64 {
    let core = current_core_id();
    return (TSSS[core].privilege_stack_table[0]).as_u64();
}

#[naked]
#[no_mangle]
pub extern "C" fn syscall_handler_64_naked() {
    unsafe {
        // core::arch::naked_asm!(
        //     "
        //     swapgs
        //     cli // disables interrupts, unsure if needed
        //     mov r12, rcx
        //     mov r13, r11
        //     mov r14, rax
        //     mov r15, rsp
        //     push rdi
        //     push rsi
        //     push rdx
        //     push r10
        //     push r8
        //     push r9
        //     call get_ring_0_rsp
        //     pop r9
        //     pop r8
        //     pop r10
        //     pop rdx
        //     pop rsi
        //     pop rdi
        //     mov rsp, rax
        //     mov rax, r14
        //     ",
        //     // gets num and args
        //     "
        //     push rbx
        //     push r9
        //     push r8
        //     push r10
        //     push rdx
        //     push rsi
        //     push rdi
        //     push rax
        //     mov rdi, rsp
        //     call syscall_handler_impl
        //     pop rax
        //     pop rdi
        //     pop rsi
        //     pop rdx
        //     pop r10
        //     pop r8
        //     pop r9
        //     pop rbx
            
        //     mov rcx, r12
        //     mov r11, r13
        //     mov rsp, r15
        //     swapgs
        //     sti
        //     sysretq
        //     "
        // )

        // core::arch::naked_asm!(
        //     "swapgs",
        //     "cli", // disables interrupts, unsure if needed
        //     "mov r12, rcx",
        //     "mov r13, r11",
        //     "mov rsp, 0xffffffff800c02f8", // this is fine for now as it wont change
        //     "push rbx",
        //     "sub rsp, 56",
        //     // gets num and args
        //     "mov [rsp + 0], rax",
        //     "mov [rsp + 8], rdi",
        //     "mov [rsp + 16], rsi",
        //     "mov [rsp + 24], rdx",
        //     "mov [rsp + 32], r10",
        //     "mov [rsp + 40], r8",
        //     "mov [rsp + 48], r9",
        //     "mov rdi, rsp",
        //     "call syscall_handler_impl",
        //     "add rsp, 56",
        //     "pop rbx",
        //     "mov rcx, r12",
        //     "mov r11, r13",
        //     "swapgs",
        //     "sysretq",
        // )


        core::arch::naked_asm!(
            "swapgs",
            "cli", // disables interrupts, unsure if needed
            "mov r12, rcx",
            "mov r13, r11",
            "mov r14, rax", // syscall num
            "mov r15, rsp",
            "push rdi",
            "push rsi",
            "push rdx",
            "push r10",
            "push r8",
            "push r9",
            "call get_ring_0_rsp", // call
            "pop r9",
            "pop r8",
            "pop r10",
            "pop rdx",
            "pop rsi",
            "pop rdi",
            "mov rsp, rax", // rax has return from get_ring_0_rsp, mov rsp
            "mov rax, r14", // return rax (syscall_number) back
            "sub rsp, 56",
            "mov [rsp + 0], rax",
            "mov [rsp + 8], rdi",
            "mov [rsp + 16], rsi",
            "mov [rsp + 24], rdx",
            "mov [rsp + 32], r10",
            "mov [rsp + 40], r8",
            "mov [rsp + 48], r9",
            "mov rdi, rsp",
            "call syscall_handler_impl",
            "add rsp, 56",
            "pop rbx",
            "mov rcx, r12",
            "mov r11, r13",
            "mov rsp, r15",
            "swapgs",
            "sysretq",
        )
    };
}

#[no_mangle]
pub fn syscall_handler_impl(syscall: *const SyscallRegisters) {
    let syscall = unsafe { &*syscall };
    serial_println!("Syscall num: {}", syscall.number);
    match syscall.number as u32 {
        SYSCALL_EXIT => sys_exit(syscall.arg1),
        SYSCALL_PRINT => sys_print(syscall.arg1 as *const u8),
        _ => {
            panic!("Unknown syscall, {}", syscall.number);
        }
    }
}

pub fn sys_exit(code: u64) {
    // TODO handle hierarchy (parent processes), resources, threads, etc.
    // TODO recursive page table walk to handle cleaning up process memory
    let event: EventInfo = current_running_event_info();

    serial_println!("Process {} exitted with code {}", event.pid, code);

    if event.pid == 0 {
        panic!("Calling exit from outside of process");
    }

    // Get PCB from PID
    let preemption_info = unsafe {
        let mut process_table = PROCESS_TABLE.write();
        let process = process_table
            .get_mut(&event.pid)
            .expect("Process not found");

        let pcb = process.pcb.get();

        (*pcb).state = ProcessState::Terminated;
        clear_process_frames(&mut *pcb);
        serial_println!("EVENT PID {}", event.pid);
        process_table.remove(&event.pid);
        serial_println!("SUCCESSFULLY REMOVED");
        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

    unsafe {
        // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
        core::arch::asm!(
            "mov rsp, {0}",
            "push {1}",
            "ret",
            in(reg) preemption_info.0,
            in(reg) preemption_info.1
        );
    }
}

// Not a real system call, but useful for testing
pub fn sys_print(buffer: *const u8) {
    // let c_str = unsafe { CStr::from_ptr(buffer as *const i8) };
    // let str_slice = c_str.to_str().expect("Invalid UTF-8 string");
    // serial_println!("Buffer: {}", str_slice);

    serial_println!("Hello World!");
}
pub fn sys_nanosleep(nanos: u64, rsp: u64) {
    sleep_process(rsp, nanos);
    x2apic::send_eoi();
}
