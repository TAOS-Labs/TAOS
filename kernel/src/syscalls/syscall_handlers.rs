use core::{arch::asm, ffi::CStr, i64, sync::atomic::AtomicI64};

use crate::{
    constants::syscalls::*, events::{current_running_event_info, EventInfo}, interrupts::{gdt::TSSS, x2apic::current_core_id}, memory::frame_allocator::with_buddy_frame_allocator, processes::{
        process::{clear_process_frames, sleep_process, ProcessState, PROCESS_TABLE},
        registers::NonFlagRegisters,
    }, serial_println, syscalls::fork::sys_fork
};

#[warn(unused)]
use crate::interrupts::x2apic;
#[allow(unused)]
use core::arch::naked_asm;

pub static TEST_EXIT_CODE: AtomicI64 = AtomicI64::new(i64::MIN);

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
pub unsafe extern "C" fn syscall_handler_64_naked() -> ! {
    naked_asm!(
        // Swap GS to load the kernel GS base.
        "swapgs",
        // Allocate 56 bytes on the stack for SyscallRegisters.
        "sub rsp, 56",
        // Save the syscall number (from RAX).
        "mov [rsp], rax",
        // Save arg1 (from RDI).
        "mov [rsp+8], rdi",
        // Save arg2 (from RSI).
        "mov [rsp+16], rsi",
        // Save arg3 (from RDX).
        "mov [rsp+24], rdx",
        // The syscall calling convention: the user’s 4th argument was originally in RCX,
        // but because syscall overwrites RCX with the return RIP, we copy RCX into r10.
        "mov r10, rcx",
        // Save arg4 (now in R10).
        "mov [rsp+32], r10",
        // Save arg5 (from R8).
        "mov [rsp+40], r8",
        // Save arg6 (from R9).
        "mov [rsp+48], r9",
        // Pass pointer to SyscallRegisters in RDI.
        "mov rdi, rsp",
        // Call the Rust syscall dispatcher.
        "call syscall_handler_impl",
        // The dispatcher returns a value in RAX; clean up the stack.
        "add rsp, 56",
        // Swap GS back.
        "swapgs",
        // Return to user mode. sysretq will use RCX (which contains the user RIP)
        // and R11 (which holds user RFLAGS).
        "sysretq",
    );
}


/// Function that routes to different syscalls
///
/// # Arguments
/// * `syscall` - A pointer to a strut containing syscall_num, arg1...arg6 as u64
///
/// # Safety
/// This function is unsafe as it must dereference `syscall` to get args
#[no_mangle]
pub unsafe extern "C" fn syscall_handler_impl(
    syscall: *const SyscallRegisters,
) -> u64 {
    serial_println!("RSP In SysHand: {:#X}", syscall as u64);

    let syscall = unsafe { &*syscall };
    serial_println!("Syscall num: {}", syscall.number);
    match syscall.number as u32 {
        SYSCALL_EXIT => {
            sys_exit(syscall.arg1 as i64);
            unreachable!("sys_exit does not return");
        }
        SYSCALL_PRINT => sys_print(syscall.arg1 as *const u8),
        SYSCALL_NANOSLEEP => sys_nanosleep(syscall.arg1, syscall.arg2),
        SYSCALL_FORK => sys_fork(),
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
        with_buddy_frame_allocator(|alloc| {
            alloc.print_free_frames();
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
