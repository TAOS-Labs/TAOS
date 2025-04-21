use core::error;

use alloc::{collections::vec_deque::{self, VecDeque}, sync::Arc};
use spin::Mutex;
use x86_64::VirtAddr;

use crate::constants::processes::NUM_SIGNALS;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalCode {
    SIGHUP    = 1,  // Hang up controlling terminal or process
    SIGINT    = 2,  // Interrupt from keyboard (Ctrl-C)
    SIGQUIT   = 3,  // Quit from keyboard (Ctrl-\), core dump
    SIGILL    = 4,  // Illegal instruction
    SIGTRAP   = 5,  // Breakpoint trap for debugging
    SIGABRT   = 6,  // Abnormal termination (abort)
    SIGBUS    = 7,  // Bus error (misaligned memory access)
    SIGFPE    = 8,  // Floating-point exception
    SIGKILL   = 9,  // Forced process termination (uncatchable)
    SIGUSR1   = 10, // User-defined signal 1
    SIGSEGV   = 11, // Invalid memory reference (segfault)
    SIGUSR2   = 12, // User-defined signal 2
    SIGPIPE   = 13, // Write to pipe with no readers
    SIGALRM   = 14, // Real-time clock timer expired
    SIGTERM   = 15, // Termination request (default kill signal)
    SIGSTKFLT = 16, // Coprocessor stack fault
    SIGCHLD   = 17, // Child process stopped or terminated
    SIGCONT   = 18, // Resume execution if stopped
    SIGSTOP   = 19, // Stop process execution (uncatchable)
    SIGTSTP   = 20, // Stop process issued from tty (Ctrl-Z)
    SIGTTIN   = 21, // Background process needs input
    SIGTTOU   = 22, // Background process needs output
    SIGURG    = 23, // Urgent socket condition
    SIGXCPU   = 24, // CPU time limit exceeded
    SIGXFSZ   = 25, // File size limit exceeded
    SIGVTALRM = 26, // Virtual timer clock expired
    SIGPROF   = 27, // Profiling timer clock expired
    SIGWINCH  = 28, // Window resize signal
    SIGIO     = 29, // I/O now possible
    SIGPWR    = 30, // Power supply failure
    SIGSYS    = 31, // Bad system call (invalid syscall)
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SigActionFlags: u32 {
        const SA_ONSTACK     = 0x0800_0000; // use alternate signal stack
        const SA_RESETHAND   = 0x8000_0000; // reset to default handler after one delivery
        const SA_RESTART     = 0x1000_0000; // restart interrupted syscalls
        const SA_SIGINFO     = 0x0000_0008; // deliver siginfo_t to handler
        const SA_NODEFER     = 0x4000_0000; // don't block signal during handler
        const SA_NOCLDWAIT   = 0x0001_0000; // don't create zombies (auto reap children)
        const SA_NOCLDSTOP   = 0x0000_0001; // don't notify parent when child stops

        // Aliases
        const SA_NOMASK      = Self::SA_NODEFER.bits();
        const SA_ONESHOT     = Self::SA_RESETHAND.bits();
    }
}



#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCode {
    SI_USER    = 0,  // Sent by kill() or raise()
    SI_KERNEL  = 1,  // Sent by the kernel
    SI_QUEUE   = 2,  // Sent by sigqueue()
    SI_TIMER   = 3,  // Timer expiration
    SI_ASYNCIO = 4,  // Asynchronous I/O completion
    SI_TKILL   = 5,  // Sent by tkill() or tgkill()
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KillFields {
    pub si_pid: u32, // Sender's PID
    pub si_uid: u32, // Sender's UID
}

#[repr(C)]
pub union SigFields {
    pub kill_source: KillFields,
    pub fault_addr: VirtAddr,
}

#[repr(C)]
pub struct SignalEntry {
    signal_code: SignalCode,
    error_code: i32,
    source_code: SourceCode,
    signal_fields: SigFields,

}

#[derive(Clone, Copy, Debug)]
pub struct SigAction {
    sa_handler: fn(u8),
    sa_flags: SigActionFlags,
    sa_mask: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum SignalHandler {
    Default,         // 0 - default action
    Ignore,          // 1 - ignore the signal
    Handler(SigAction), // function pointer to user-provided handler
}


pub struct SignalDescriptor {
    pending_signals: VecDeque<SignalEntry>, // queue for pending signals sent to process
    blocked_signals: u32, // a bitmap for the 32 different signals Linux handles
    sas_ss_sp: VirtAddr, // TODO: support a separate stack for some signal handling
    sas_ss_size: u64,
    signal_handlers: [Arc<Mutex<SignalHandler>>; NUM_SIGNALS],
}

impl SignalDescriptor {
    pub fn new(
        blocked_signals: u32,
        sas_ss_sp: VirtAddr,
        sas_ss_size: u64,
    ) -> Self {
        Self {
            pending_signals: VecDeque::new(),
            blocked_signals: blocked_signals,
            sas_ss_sp: sas_ss_sp,
            sas_ss_size: sas_ss_size,
            // populate signal handlers with originally all default handlers
            signal_handlers: core::array::from_fn(|_| Arc::new(Mutex::new(SignalHandler::Default))),
        }
    }

    pub fn register_sigaction(&mut self, code: SignalCode, sa_handler: fn(u8), sa_flags: SigActionFlags, sa_mask: u32) {
        let sigaction = SigAction {
            sa_handler: sa_handler,
            sa_flags: sa_flags,
            sa_mask: sa_mask,

        };
        // signals are 1-indexed so subtract 1.
        self.signal_handlers[(code as usize) - 1] = Arc::new(Mutex::new(SignalHandler::Handler(sigaction)));
    }

    pub fn send_signal(&mut self, signal_code: SignalCode, error_code: i32, source_code: SourceCode, signal_fields: SigFields) {
        let signal_entry = SignalEntry {
            signal_code: signal_code,
            error_code: error_code,
            source_code: source_code,
            signal_fields: signal_fields,
        };
        self.pending_signals.push_back(signal_entry);
    }
}