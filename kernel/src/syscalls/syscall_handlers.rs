use crate::{
    constants::syscalls::{SYSCALL_EXIT, SYSCALL_PRINT},
    events::{current_running_event_info, spawn, yield_now, EventInfo, JoinHandle},
    interrupts::x2apic,
    processes::process::{clear_process_frames, ProcessState, PROCESS_TABLE},
    serial_println,
};
use alloc::{boxed::Box, collections::BTreeMap};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use spin::RwLock;

#[derive(Debug)]
pub enum Error {
    InvalidCall,
    WouldBlock,
    NamespaceError,
}

// Store the syscall state for a process
struct SyscallState {
    join_handle: JoinHandle<Result<usize, Error>>,
    waker: Option<Waker>,
}

pub struct SyscallHandler {
    // Map of PIDs to their syscall state
    syscalls: RwLock<BTreeMap<u32, SyscallState>>,
}

impl SyscallHandler {
    pub const fn new() -> Self {
        Self {
            syscalls: RwLock::new(BTreeMap::new()),
        }
    }

    // Start a syscall and block the process
    pub fn start_syscall(
        &self,
        pid: u32,
        handle: JoinHandle<Result<usize, Error>>,
    ) -> Poll<Result<usize, Error>> {
        self.syscalls.write().insert(
            pid,
            SyscallState {
                join_handle: handle,
                waker: None,
            },
        );
        Poll::Pending
    }
}

static SYSCALL_HANDLER: SyscallHandler = SyscallHandler::new();

// Future that waits for syscall completion
struct SyscallFuture {
    pid: u32,
}

impl Future for SyscallFuture {
    type Output = Result<usize, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut syscalls = SYSCALL_HANDLER.syscalls.write();

        if let Some(state) = syscalls.get_mut(&self.pid) {
            // Poll the join handle
            let result = Pin::new(&mut state.join_handle).poll(cx);

            match result {
                Poll::Ready(Ok(syscall_result)) => {
                    // Syscall completed, remove state and return result
                    syscalls.remove(&self.pid);
                    Poll::Ready(syscall_result)
                }
                Poll::Ready(Err(_)) => {
                    // Handle task error
                    syscalls.remove(&self.pid);
                    Poll::Ready(Err(Error::InvalidCall))
                }
                Poll::Pending => {
                    // Store waker and keep waiting
                    state.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        } else {
            Poll::Ready(Err(Error::InvalidCall))
        }
    }
}

#[no_mangle]
pub extern "C" fn dispatch_syscall() {
    let (syscall_num, arg1, arg2, arg3): (u32, usize, usize, usize);

    unsafe {
        core::arch::asm!(
            "mov {0:r}, rax",
            "mov {1}, rdi",
            "mov {2}, rsi",
            "mov {3}, rdx",
            out(reg) syscall_num,
            out(reg) arg1,
            out(reg) arg2,
            out(reg) arg3,
        );
    }

    let cpuid = x2apic::current_core_id() as u32;
    let event = current_running_event_info(cpuid);
    let pid = event.pid;

    let handler = match syscall_num {
        SYSCALL_PRINT => {
            let fut: Pin<Box<dyn Future<Output = Result<usize, Error>> + Send>> =
                Box::pin(handle_read(pid, arg1, arg2, arg3));
            Some(fut)
        }
        SYSCALL_EXIT => {
            sys_exit();
            None
        }
        _ => None,
    };

    if let Some(handler) = handler {
        // Spawn the handler and get join handle
        let join_handle = spawn(cpuid, handler, 1);

        // Start syscall and block process
        let _ = SYSCALL_HANDLER.start_syscall(pid, join_handle);

        // Create future to wait for completion
        let syscall_future = SyscallFuture { pid };

        // Spawn the waiting future
        spawn(cpuid, syscall_future, 1);
    }

    yield_now();
}

async fn handle_read(_: u32, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    serial_println!("Hello, world!");
    Ok(0)
}

fn sys_exit() {
    // TODO handle hierarchy (parent processes), resources, threads, etc.
    // TODO recursive page table walk to handle cleaning up process memory
    let cpuid: u32 = x2apic::current_core_id() as u32;
    let event: EventInfo = current_running_event_info(cpuid);

    if event.pid == 0 {
        panic!("Calling exit from outside of process");
    }

    serial_println!("Process {} exit", event.pid);

    // Get PCB from PID
    let preemption_info = unsafe {
        let mut process_table = PROCESS_TABLE.write();
        let process = process_table
            .get_mut(&event.pid)
            .expect("Process not found");

        let pcb = process.pcb.get();

        (*pcb).state = ProcessState::Terminated;
        clear_process_frames(&mut *pcb);
        process_table.remove(&event.pid);
        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

    unsafe {
        // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
        core::arch::asm!(
            "mov rsp, {0}",
            "push {1}",
            "stc",          // Use carry flag as sentinel to run_process that we're exiting
            "ret",
            in(reg) preemption_info.0,
            in(reg) preemption_info.1
        );
    }
}
