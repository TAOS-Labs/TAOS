use core::ffi::CStr;

use alloc::collections::btree_map::BTreeMap;
use lazy_static::lazy_static;
use spin::lock_api::Mutex;

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

use crate::{
    constants::syscalls::*,
    events::{
        current_running_event, current_running_event_info, futures::await_on::AwaitProcess,
        get_runner_time, yield_now, EventInfo,
    },
    interrupts::x2apic,
    memory::frame_allocator::with_buddy_frame_allocator,
    processes::{
        process::{sleep_process_int, sleep_process_syscall, ProcessState, PROCESS_TABLE},
        registers::NonFlagRegisters,
    },
    serial_println,
    syscalls::{fork::sys_fork, memorymap::sys_mmap},
};

use core::arch::naked_asm;

use super::memorymap::sys_munmap;

lazy_static! {
    pub static ref EXIT_CODES: Mutex<BTreeMap<u32, i64>> = Mutex::new(BTreeMap::new());
}

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

/// Naked syscall handler that switches to a valid kernel stack (saving
/// the user stack in some TSS), saves register values, sets up
/// correct arguments, and dispatches to a syscall handler
///
/// # Return
/// This function never returns normally as it performs a sysretq
///
/// # Safety
/// This function is unsafe as it manually saves state and switches stacks
#[naked]
#[no_mangle]
pub unsafe extern "C" fn syscall_handler_64_naked() -> ! {
    naked_asm!(
        "cli", // Disable interrupts for now (don't want to be preempted here)
        // Swap GS to load the kernel GS base.
        "swapgs",
        // RSP2 in the TSS is scratch space - store userspace RSP for later
        "mov qword ptr gs:[20], rsp",
        // TODO WE NEED TO USE KERNEL STACK HERE
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
        "sti",
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
    let reg_vals = unsafe { &*reg_vals };

    match syscall.number as u32 {
        SYSCALL_EXIT => {
            sys_exit(syscall.arg1 as i64);
            unreachable!("sys_exit does not return");
        }
        SYSCALL_PRINT => sys_print(syscall.arg1 as *const u8),
        SYSCALL_NANOSLEEP => sys_nanosleep_64(syscall.arg1, reg_vals),
        SYSCALL_FORK => sys_fork(reg_vals),
        SYSCALL_MMAP => sys_mmap(
            syscall.arg1,
            syscall.arg2,
            syscall.arg3,
            syscall.arg4,
            syscall.arg5 as i64,
            syscall.arg6,
        ),
        SYSCALL_WAIT => block_on(sys_wait(syscall.arg1 as u32)),
        SYSCALL_MUNMAP => sys_munmap(syscall.arg1, syscall.arg2),
        _ => {
            panic!("Unknown syscall, {}", syscall.number);
        }
    }
}

pub fn sys_exit(code: i64) -> Option<u64> {
    // TODO handle hierarchy (parent processes), resources, threads, etc.

    // Used for testing
    if code == -1 {
        panic!("Exited with code -1");
    }

    let event: EventInfo = current_running_event_info();

    serial_println!("Process {} exited with code {}", event.pid, code);
    // This is for testing; this way, we can write binaries that conditionally fail tests
    if code == -1 {
        panic!("Unknown exit code, something went wrong")
    }

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

        // clear_process_frames(&mut *pcb);
        with_buddy_frame_allocator(|alloc| {
            alloc.print_free_frames();
        });

        EXIT_CODES.lock().insert(event.pid, code);

        process_table.remove(&event.pid);
        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

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

/// Handle a nanosleep system call entered via int 0x80
/// Uses interrupt stack to restore state
pub fn sys_nanosleep_32(nanos: u64, rsp: u64) -> u64 {
    sleep_process_int(nanos, rsp);
    x2apic::send_eoi();

    0
}

/// Handle a nanosleep system call entered via syscall
/// Uses manually-created NonFlagRegisters struct to restore state
pub fn sys_nanosleep_64(nanos: u64, reg_vals: &NonFlagRegisters) -> u64 {
    sleep_process_syscall(nanos, reg_vals);

    0
}

/// Wait on a process to finish
pub async fn sys_wait(pid: u32) -> u64 {
    let _waiter = AwaitProcess::new(
        pid,
        get_runner_time(3_000_000_000),
        current_running_event().unwrap(),
    )
    .await;

    return *(EXIT_CODES.lock().get(&pid).unwrap()) as u64;
}

/// Helper function for sys_wait, not sure if necessary
/// TODO Ask Kiran if necessary
fn noop_raw_waker() -> RawWaker {
    fn clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }
    fn wake(_: *const ()) {}
    fn wake_by_ref(_: *const ()) {}
    fn drop(_: *const ()) {}
    let vtable = &RawWakerVTable::new(clone, wake, wake_by_ref, drop);
    RawWaker::new(core::ptr::null(), vtable)
}
/// Helper function for sys_wait, not sure if necessary
fn block_on<F: Future>(mut future: F) -> F::Output {
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // Safety: we’re not moving the future while polling.
    let mut future = unsafe { Pin::new_unchecked(&mut future) };
    loop {
        if let Poll::Ready(val) = future.as_mut().poll(&mut cx) {
            return val;
        }
        yield_now();
    }
}
