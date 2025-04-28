use core::{arch::naked_asm, error, future::pending};

use alloc::{collections::{btree_map::BTreeMap, vec_deque::{self, VecDeque}}, sync::Arc};
use spin::Mutex;
use x86_64::VirtAddr;

use crate::{constants::processes::NUM_SIGNALS, serial_println, syscalls::syscall_handlers::sys_exit};

use super::{process::{get_current_pid, PROCESS_TABLE}, registers::ForkingRegisters};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
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
    SIGPRINT    = 31, // Bad system call (invalid syscall)
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

pub fn signal_num_to_code(signal_num: u32) -> Option<SignalCode> {
    match signal_num {
        1 => Some(SignalCode::SIGHUP),
        2 => Some(SignalCode::SIGINT),
        3 => Some(SignalCode::SIGQUIT),
        4 => Some(SignalCode::SIGILL),
        5 => Some(SignalCode::SIGTRAP),
        6 => Some(SignalCode::SIGABRT),
        7 => Some(SignalCode::SIGBUS),
        8 => Some(SignalCode::SIGFPE),
        9 => Some(SignalCode::SIGKILL),
        10 => Some(SignalCode::SIGUSR1),
        11 => Some(SignalCode::SIGSEGV),
        12 => Some(SignalCode::SIGUSR2),
        13 => Some(SignalCode::SIGPIPE),
        14 => Some(SignalCode::SIGALRM),
        15 => Some(SignalCode::SIGTERM),
        16 => Some(SignalCode::SIGSTKFLT),
        17 => Some(SignalCode::SIGCHLD),
        18 => Some(SignalCode::SIGCONT),
        19 => Some(SignalCode::SIGSTOP),
        20 => Some(SignalCode::SIGTSTP),
        21 => Some(SignalCode::SIGTTIN),
        22 => Some(SignalCode::SIGTTOU),
        23 => Some(SignalCode::SIGURG),
        24 => Some(SignalCode::SIGXCPU),
        25 => Some(SignalCode::SIGXFSZ),
        26 => Some(SignalCode::SIGVTALRM),
        27 => Some(SignalCode::SIGPROF),
        28 => Some(SignalCode::SIGWINCH),
        29 => Some(SignalCode::SIGIO),
        30 => Some(SignalCode::SIGPWR),
        31 => Some(SignalCode::SIGPRINT),
        _ => None, // Return None for invalid signal numbers
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KillFields {
    pub si_pid: u32, // Sender's PID
    pub si_uid: u32, // Sender's UID
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SigFields {
    pub kill_source: KillFields,
    pub fault_addr: VirtAddr,
}

impl core::fmt::Debug for SigFields {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        unsafe {
            write!(
                f,
                "SigFields {{ kill_source: {:#?}, fault_addr: {:#?} }}",
                self.kill_source, self.fault_addr
            )
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
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


#[derive(Debug, Clone)]
pub struct SignalDescriptor {
    pending_signals: BTreeMap<SignalCode, VecDeque<SignalEntry>>,
    blocked_signals: u32, // a bitmap for the 32 different signals Linux handles
    sas_ss_sp: VirtAddr, // TODO: support a separate stack for some signal handling
    sas_ss_size: u64,
    signal_handlers: [Arc<Mutex<SignalHandler>>; NUM_SIGNALS],
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn sigreturn_trampoline() -> ! {
    naked_asm!(
        // sigreturn number is 15
        "mov rax, 15",
        "syscall",
    )
}

type UserspaceSignalHandler = extern "C" fn();

pub fn sys_sigreturn() -> u64 {
    panic!();
}

#[no_mangle]
pub extern "C" fn handle_signal_in_userspace(handler: UserspaceSignalHandler, user_rsp: u64, kernel_rsp: u64) {
    serial_println!("Handling some shit");
    // 1. Set up user-space stack frame with just the return address
    // Adjust user stack pointer to make room for return address (8 bytes)
    let adjusted_user_rsp = user_rsp - 8;
    
    // Push the trampoline address onto the user stack as return address
    unsafe {
        // Address of your trampoline function
        let trampoline_addr: u64 = sigreturn_trampoline as *const () as u64;
        
        // Store the trampoline address on the user stack
        *(adjusted_user_rsp as *mut u64) = trampoline_addr;
    }
    
    // 2. Set up instruction pointer to point to the signal handler
    unsafe {
        // Calculate offset to RIP in the saved context
        // With your stack layout, we need to calculate the correct offset
        // Based on 15 manually pushed registers and hardware-pushed values
        
        // You'll need to verify this offset in your specific implementation
        // This assumes kernel_rsp points to the location after all pushes
        const RIP_OFFSET: u64 = 15 * 8; // Offset from kernel_rsp to where RIP is saved
        
        // Cast handler to u64 address
        let handler_addr: u64 = handler as *const () as u64;

        serial_println!("handler addr is {}", handler_addr);
        
        // Modify the saved RIP
        *((kernel_rsp + RIP_OFFSET) as *mut u64) = handler_addr;

        serial_println!("Set up RIP in address {:X}", (kernel_rsp + RIP_OFFSET));
        
        // Also update the saved user stack pointer
        const RSP_OFFSET: u64 = (15 + 3) * 8; // Offset to RSP
        *((kernel_rsp + RSP_OFFSET) as *mut u64) = adjusted_user_rsp;
    }
    
    // We're not actually calling the handler here
    // Just setting up the context so iretq will transfer control to it
}

pub fn default_handle_sigsegv() {
    serial_println!("Segmentation fault.");
    sys_exit(-1, &ForkingRegisters::default());
}

pub extern "C" fn default_handle_sigprint() {
    serial_println!("In SigPrint! Hello!");
    panic!();
}



impl SignalDescriptor {
    pub fn new(
        blocked_signals: u32,
        sas_ss_sp: VirtAddr,
        sas_ss_size: u64,
    ) -> Self {
        Self {
            pending_signals: BTreeMap::new(),
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
        if !self.pending_signals.contains_key(&signal_code) {
            self.pending_signals.insert(signal_code, VecDeque::new());
        }
        self.pending_signals.get_mut(&signal_code).unwrap().push_back(signal_entry)
    }

    pub fn handle_signal(&mut self, user_rsp: u64, kernel_rsp: u64) {
        let mut signal: Option<SignalEntry> = None;
        let mut should_remove = false;
        let mut remove_key = SignalCode::SIGPRINT;
        // iterate through BTreeMap form lowest keys to highest based off priorities to pick most pending signal
        for (signal_code, entry_queue) in self.pending_signals.iter_mut() {
            let blocked =  (self.blocked_signals >> (*signal_code as usize - 1) & 1) == 1;
            if !blocked {
                assert!(!entry_queue.is_empty());
                signal = entry_queue.pop_front();
                if entry_queue.is_empty() {
                    remove_key = *signal_code;
                    should_remove = true;
                }
                break;
            }
        }

        if should_remove {
            self.pending_signals.remove(&remove_key);
        }

        if signal.is_none() {
            return;
        }

        let signal = signal.unwrap();
        let handler = self.signal_handlers[signal.signal_code as usize - 1].lock().clone();

        match signal.signal_code {
            SignalCode::SIGSEGV => {
                if let SignalHandler::Default = handler {
                    default_handle_sigsegv();
                }
            }
            SignalCode::SIGPRINT => {
                if let SignalHandler::Default = handler {
                    handle_signal_in_userspace(default_handle_sigprint, user_rsp, kernel_rsp);
                }
            }

            _ => {
                return;
            }
            
        }



    }
}


pub fn sys_kill(pid: u32, sig: u32) -> u64 {
    serial_println!("helloooooooooooooooooooooooo");
    let mut process = {
        let process_table = PROCESS_TABLE.read();
        let process = process_table
            .get(&pid);
        if process.is_none() {
            return 1;
        }
        process.unwrap().clone()
    };

    let pcb = unsafe { &mut *process.pcb.get() };

    let current_pid = get_current_pid();
    // TODO: Figure out how to properly populate other fields
    let sig_field = SigFields{kill_source: KillFields { si_pid: current_pid, si_uid: 0 }};
    let signal_code = signal_num_to_code(sig);
    if signal_code.is_none() {
        return 1;
    }
    serial_println!("HELLOOO");
    pcb.signal_descriptor.send_signal(signal_code.unwrap(), 0,SourceCode::SI_USER, sig_field);
    0
}