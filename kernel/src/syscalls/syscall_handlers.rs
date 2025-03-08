use core::{ffi::CStr, i64, sync::atomic::AtomicI64};

use crate::{
    constants::syscalls::*,
    events::{current_running_event_info, current_running_event_pid, EventInfo},
    interrupts::{gdt::TSSS, x2apic::{self, current_core_id}},
    memory::frame_allocator::with_bitmap_frame_allocator,
    processes::{
        process::{clear_process_frames, sleep_process, ProcessState, PROCESS_TABLE},
        registers::NonFlagRegisters,
    },
    serial_println,
};

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
        // RSP2 in the TSS is scratch space - store userspace RSP for later
        "mov qword ptr gs:[20], rsp",
        // Use kernel stack
        "mov rsp, qword ptr gs:[4]",
        // Allocate 56 bytes on the stack for SyscallRegisters.
        // Save important registers
        "push rbp",
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rbx",
        "mov r12, qword ptr gs:[20]", // get user rsp and push it on stack for fork
        "push r12",
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
        "mov rsi, rsp",
        "add rsi, 56",
        // Call the Rust syscall dispatcher.
        "call syscall_handler_impl",
        // The dispatcher returns a value in RAX; clean up the stack.
        "add rsp, 56",
        // Restore important regs
        "add rsp, 8", // we don't care about rsp that was pushed for fork
        "pop rbx",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop r11",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",
        "pop rbp",
        // Swap GS back.
        "mov rsp, qword ptr gs:[20]",
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
    reg_vals: *const NonFlagRegisters,
) -> u64 {
    let syscall = unsafe { &*syscall };
    let _ = unsafe { &*reg_vals };
    serial_println!(
        "Syscall num: {}, by PID: {}",
        syscall.number,
        current_running_event_pid()
    );
    match syscall.number as u32 {
        SYSCALL_EXIT => {
            sys_exit(syscall.arg1 as i64);
            unreachable!("sys_exit does not return");
        }
        SYSCALL_PRINT => sys_print(syscall.arg1 as *const u8),
        SYSCALL_NANOSLEEP => sys_nanosleep(syscall.arg1, syscall.arg2),
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
        core::arch::asm!("swapgs");
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

pub fn sys_nanosleep(nanos: u64, rsp: u64) -> u64 {
    sleep_process(rsp, nanos);
    x2apic::send_eoi();

    0
}
