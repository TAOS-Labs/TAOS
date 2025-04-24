use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

use alloc::boxed::Box;

use crate::{
    events::current_running_event_info,
    processes::{
        process::{ProcessState, PROCESS_TABLE},
        registers::ForkingRegisters,
    },
};

/// Helper function for sys_wait, not sure if necessary
/// TODO make this into a real block (bring back pawait)
pub fn spin_on<F: Future>(mut future: F) -> F::Output {
    let waker = unsafe { Waker::from_raw(anoop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // Safety: we’re not moving the future while polling.
    let mut future = unsafe { Pin::new_unchecked(&mut future) };
    loop {
        if let Poll::Ready(val) = future.as_mut().poll(&mut cx) {
            return val;
        }
    }
}

pub(crate) fn block_on<F: Future<Output = u64>>(future: F, reg_vals: &ForkingRegisters) -> u64 {
    // Move future to heap
    let fut = Box::from(future);

    unsafe { block_on_helper(Box::into_raw(fut), reg_vals) }
}

fn anoop_raw_waker() -> RawWaker {
    fn clone(_: *const ()) -> RawWaker {
        anoop_raw_waker()
    }
    fn wake(_: *const ()) {}
    fn wake_by_ref(_: *const ()) {}
    fn drop(_: *const ()) {}
    let vtable = &RawWakerVTable::new(clone, wake, wake_by_ref, drop);
    RawWaker::new(core::ptr::null(), vtable)
}

unsafe fn block_on_helper<F: Future<Output = u64> + ?Sized>(
    fut_ptr: *mut F,
    reg_vals: *const ForkingRegisters,
) -> u64 {
    // TODO option to "spin poll" with max iterations, to prevent exessive yielding
    let waker = unsafe { Waker::from_raw(anoop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);

    let future = unsafe { Pin::new_unchecked(&mut *fut_ptr) };

    // TODO remove
    if let Poll::Ready(val) = future.poll(&mut cx) {
        // We haven't yet yielded, so act like normal
        return val;
    }

    let preemption_info: (u64, u64) = {
        let pid = current_running_event_info().pid;
        let mut process_table = PROCESS_TABLE.write();
        let process = process_table.get_mut(&pid).expect("Process not found");

        let pcb = process.pcb.get();

        (*pcb).state = ProcessState::Ready;
        // TODO could also set state to Blocked (and invoke block_process??)
        // For now just poll from scheduler (and thus allow other things to poll in-between)

        (*pcb).registers.rbp = (*reg_vals).rbp;
        (*pcb).registers.r15 = (*reg_vals).r15;
        (*pcb).registers.r14 = (*reg_vals).r14;
        (*pcb).registers.r13 = (*reg_vals).r13;
        (*pcb).registers.r12 = (*reg_vals).r12;
        (*pcb).registers.r11 = (*reg_vals).r11;
        (*pcb).registers.r10 = (*reg_vals).r10;
        (*pcb).registers.r9 = (*reg_vals).r9;
        (*pcb).registers.r8 = (*reg_vals).r8;
        (*pcb).registers.rdi = (*reg_vals).rdi;
        (*pcb).registers.rsi = (*reg_vals).rsi;
        (*pcb).registers.rdx = (*reg_vals).rdx;
        (*pcb).registers.rcx = (*reg_vals).rcx;
        (*pcb).registers.rbx = (*reg_vals).rbx;

        (*pcb).registers.rsp = (*reg_vals).rsp;

        (*pcb).reentry_arg1 = fut_ptr as *const () as u64;
        (*pcb).reentry_rip = retry_block_on_helper::<F> as usize as u64;
        (*pcb).in_kernel = true;

        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

    // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
    core::arch::asm!(
        "mov rsp, {0}",
        "push {1}",
        "swapgs",
        "ret",
        in(reg) preemption_info.0,
        in(reg) preemption_info.1,
    );

    unreachable!("If future is not ready, should yield back to scheduler")
}

/// # Safety
/// Only public for access from processes; should not be called directly
pub unsafe extern "C" fn retry_block_on_helper<F: Future<Output = u64> + ?Sized>(
    fut_ptr: *mut F,
) -> ! {
    // TODO option to "spin poll" with max iterations, to prevent exessive yielding
    let waker = unsafe { Waker::from_raw(anoop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);

    let future = unsafe { Pin::new_unchecked(&mut *fut_ptr) };

    // TODO remove
    if let Poll::Ready(val) = future.poll(&mut cx) {
        let pid = current_running_event_info().pid;
        let regs = {
            let mut process_table = PROCESS_TABLE.write();
            let process = process_table.get_mut(&pid).expect("Process not found");

            let pcb = process.pcb.get();
            (*pcb).in_kernel = false;
            (*pcb).state = ProcessState::Running;

            &(*pcb).registers
        };

        // We've yielded before, so stack is unreliable
        core::arch::asm!(
            // Restore registers directly from PCB
            "mov rbx, [rcx+8]",
            "mov rdx, [rcx+24]",
            "mov rsi, [rcx+32]",
            "mov rdi, [rcx+40]",
            "mov r8, [rcx+48]",
            "mov r9, [rcx+56]",
            "mov r10, [rcx+64]",
            "mov r11, [rcx+72]",
            "mov r12, [rcx+80]",
            "mov r13, [rcx+88]",
            "mov r14, [rcx+96]",
            "mov r15, [rcx+104]",

            "mov rsp, [rcx+120]",
            "mov rcx, [rcx+16]",

            // Swap GS back.
            "swapgs",
            // Return to user mode. sysretq will use RCX (which contains the user RIP)
            // and R11 (which holds user RFLAGS).
            "sti",
            "sysretq",
            in("rax") val,
            in("rcx") regs
        );

        unreachable!("If future is ready, should return to process")
    }

    let preemption_info: (u64, u64) = {
        let pid = current_running_event_info().pid;
        let mut process_table = PROCESS_TABLE.write();
        let process = process_table.get_mut(&pid).expect("Process not found");

        let pcb = process.pcb.get();

        (*pcb).state = ProcessState::Ready;
        // TODO could also set state to Blocked (and invoke block_process??)
        // For now just poll from scheduler (and thus allow other things to poll in-between)

        // No need to save user registers; must have done so already last time we yielded

        // TODO reentry_rip
        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

    // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
    core::arch::asm!(
        "mov rsp, {0}",
        "push {1}",
        "swapgs",
        "ret",
        in(reg) preemption_info.0,
        in(reg) preemption_info.1,
    );

    unreachable!("If future is not ready, should yield back to scheduler")
}
