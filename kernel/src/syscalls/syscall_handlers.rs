use core::{ffi::CStr, i64, sync::atomic::AtomicI64};

use crate::{
    constants::syscalls::*, events::{current_running_event_info, EventInfo}, interrupts::{gdt::TSSS, x2apic::current_core_id}, memory::frame_allocator::with_bitmap_frame_allocator, processes::process::{clear_process_frames, sleep_process, ProcessState, PROCESS_TABLE}, serial_println, syscalls::fork::sys_fork, processes::registers::NonFlagRegisters
};

#[warn(unused)]
use crate::interrupts::x2apic;
#[allow(unused)]
use core::arch::naked_asm;

pub static TEST_EXIT_CODE: AtomicI64= AtomicI64::new(i64::MIN);

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
    ((TSSS[core].privilege_stack_table[0]).as_u64()) & !15
}

#[naked]
#[no_mangle]
pub extern "C" fn syscall_handler_64_naked() {
    unsafe {
        core::arch::naked_asm!(
            "
            swapgs
            // push every register so it can be pushed to kernel stack later
            // we don't care about rax because the return value of syscall will be returned there
            push rsp
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


            call get_ring_0_rsp // call

            // rax now has kernel rsp
            // open up the kernel rsp to store all registers
            mov r12, rax
            sub r12, 128
            mov rdi, r12
            mov rsi, rsp
            mov rcx, 16
            rep   movsq

            // rsp is now saved in r13 - callee-saved register
            mov r13, rsp

            // switch rsp to kernel rsp
            mov rsp, r12

            // we overwrote rax, rdi, and rsi which are parameters - restore them
            mov rax, [rsp]
            mov rdi, [rsp+40]
            mov rsi, [rsp+32]

            // open up stack frame for syscall params
            sub rsp, 56
            mov [rsp + 0], rax
            mov [rsp + 8], rdi
            mov [rsp + 16], rsi
            mov [rsp + 24], rdx
            mov [rsp + 32], r10
            mov [rsp + 40], r8
            mov [rsp + 48], r9
            
            // pass in pointer to syscall params and register values
            mov rdi, rsp
            mov rsi, rsp
            add rsi, 56
            call syscall_handler_impl

            // add for both params and register values
            add rsp, 176

            // restore user rsp
            mov rsp, r13

            // pop back all original register values
            add rsp, 8 // we don't want to overwrite rax
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
            add rsp, 8 // we don' need to update rsp
            swapgs
            sysretq
            "
        )
    };
}

/// Function that routes to different syscalls
///
/// # Arguments
/// * `syscall` - A pointer to a strut containing syscall_num, arg1...arg6 as u64
///
/// # Safety
/// This function is unsafe as it must dereference `syscall` to get args
#[no_mangle]
pub unsafe extern "C" fn syscall_handler_impl(syscall: *const SyscallRegisters, reg_vals: *const NonFlagRegisters) -> u64 {
    let regs = unsafe {&*reg_vals};
    let syscall = unsafe { &*syscall };
    serial_println!("Syscall num: {}", syscall.number);
    match syscall.number as u32 {
        SYSCALL_EXIT => {
            sys_exit(syscall.arg1 as i64);
            unreachable!("sys_exit does not return");
        }
        SYSCALL_PRINT => sys_print(syscall.arg1 as *const u8),
        SYSCALL_NANOSLEEP => sys_nanosleep(syscall.arg1, syscall.arg2),
        SYSCALL_FORK => sys_fork(regs),
        _ => {
            panic!("Unknown syscall, {}", syscall.number);
        }
    }
}

pub fn sys_exit(code: i64) -> Option<u64> {
    // TODO handle hierarchy (parent processes), resources, threads, etc.

    // Used for testing
    if code == -1 {
        panic!("Exitted with code -1");
    }

    let event: EventInfo = current_running_event_info();

    // This is for testing; this way, we can write binaries that conditionally fail tests
    if code == -1 {
        panic!("Unknown exit code, something went wrong")
    }

    if event.pid == 0 {
        panic!("Calling exit from outside of process");
    }

    serial_println!("Process {} exitted with code {}", event.pid, code);

    // Get PCB from PID
    let preemption_info = unsafe {
        let mut process_table = PROCESS_TABLE.write();
        let process = process_table
            .get_mut(&event.pid)
            .expect("Process not found");

        let pcb = process.pcb.get();

        (*pcb).state = ProcessState::Terminated;
        clear_process_frames(&mut *pcb);
        with_bitmap_frame_allocator(|alloc| {
            alloc.print_bitmap_free_frames();
        });
 
        process_table.remove(&event.pid);
        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

    #[cfg(test)]
    {
        TEST_EXIT_CODE.store(code, core::sync::atomic::Ordering::SeqCst);
    }

    unsafe {
        // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
        core::arch::asm!(
            "mov rsp, {0}",
            "push {1}",
            "stc",          // Use carry flag as sentinel to run_process that we're exiting
            // "ret",
            in(reg) preemption_info.0,
            in(reg) preemption_info.1
        );
    }

    if code == -1 {
        panic!("Bad error code!");
    }

    unsafe {
        core::arch::asm!("ret");
    }

    Some(code as u64)
}


// Not a real system call, but useful for testing
pub fn sys_print(buffer: *const u8) -> u64 {
    let c_str = unsafe { CStr::from_ptr(buffer as *const i8) };
    let str_slice = c_str.to_str().expect("Invalid UTF-8 string");
    serial_println!("Buffer: {}", str_slice);

    0
}

// hey gang
pub fn sys_nanosleep(nanos: u64, rsp: u64) -> u64 {
    sleep_process(rsp, nanos);
    // x2apic::send_eoi();

    0
}
