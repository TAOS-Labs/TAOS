use core::ffi::CStr;

use alloc::{collections::btree_map::BTreeMap, slice, string::ToString, vec};
use lazy_static::lazy_static;
use pc_keyboard::{DecodedKey, KeyCode, KeyState};
use spin::Mutex;
use x86_64::{
    align_up,
    registers::model_specific::{FsBase, Msr},
    structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB},
    VirtAddr,
};

use crate::{
    constants::{memory::PAGE_SIZE, syscalls::*},
    devices::ps2_dev::keyboard,
    events::{
        current_running_event, current_running_event_info, futures::await_on::AwaitProcess,
        get_runner_time, nanosleep_current_event, schedule_kernel, schedule_process, yield_now,
        EventInfo,
    },
    filesys::{
        get_file,
        syscalls::{sys_creat, sys_open},
        FileSystem, OpenFlags, FILESYSTEM,
    },
    interrupts::x2apic::{send_eoi, X2APIC_IA32_FS_BASE, X2APIC_IA32_GSBASE},
    memory::paging::create_mapping,
    processes::{
        process::{
            create_process, sleep_process_int, sleep_process_syscall, with_current_pcb,
            ProcessState, PROCESS_TABLE,
        },
        registers::ForkingRegisters,
    },
    serial_print, serial_println,
    syscalls::{
        block::block_on,
        fork::sys_fork,
        memorymap::{sys_mmap, MmapFlags, ProtFlags},
    },
};

use core::arch::naked_asm;

use super::memorymap::{sys_mprotect, sys_munmap};

lazy_static! {
    pub static ref EXIT_CODES: Mutex<BTreeMap<u32, i64>> = Mutex::new(BTreeMap::new());
    pub static ref REGISTER_VALUES: Mutex<BTreeMap<u32, ForkingRegisters>> =
        Mutex::new(BTreeMap::new());
    pub static ref PML4_FRAMES: Mutex<BTreeMap<u32, PhysFrame<Size4KiB>>> =
        Mutex::new(BTreeMap::new());
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

pub struct ConstUserPtr<T>(pub *const T);
unsafe impl<T> Send for ConstUserPtr<T> {}
impl<T> From<u64> for ConstUserPtr<T> {
    fn from(value: u64) -> Self {
        ConstUserPtr(value as *const T)
    }
}

pub struct MutUserPtr<T>(pub *mut T);
unsafe impl<T> Send for MutUserPtr<T> {}
impl<T> From<u64> for MutUserPtr<T> {
    fn from(value: u64) -> Self {
        MutUserPtr(value as *mut T)
    }
}

/// Reload IA32_FS_BASE with pcb.fs_base (called from naked stub)
#[no_mangle]
pub extern "C" fn reload_fs_base() {
    use x86_64::registers::model_specific::Msr;

    const IA32_FS_BASE: u32 = 0xC000_0100;

    // with_current_pcb gives us &mut PCB for the thread that owns this syscall
    with_current_pcb(|pcb| unsafe {
        Msr::new(IA32_FS_BASE).write(pcb.fs_base);
        FsBase::write(VirtAddr::new(pcb.fs_base));
    });
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
#[unsafe(naked)]
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
        // We shouldn't be doing this
        //"mov r10, rcx",
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
        // --- reload FS_BASE just before we return to user ----------------
        // REMOVED THIS AS IT BREAKS THINGS WITH NEW RET; ESSENITALLY UNDOES ARCH_PRCTL
        // "push rax",
        // "push rdi",
        // "push rsi",
        // "push rdx",
        // "push rcx",
        // "push r8",
        // "push r9",
        // "push r10",
        // "push r11",
        // "call reload_fs_base", // -> writes IA32_FS_BASE = pcb.fs_base
        // "pop r11",
        // "pop r10",
        // "pop r9",
        // "pop r8",
        // "pop rcx",
        // "pop rdx",
        // "pop rsi",
        // "pop rdi",
        // "pop rax", // Return to user mode. sysretq will use RCX (which contains the user RIP)
        // // and R11 (which holds user RFLAGS).
        "sti",
        "sysretq",
    );
}

/// Function that routes to different syscalls
///
/// # Arguments
/// * `syscall` - A pointer to a strut containing syscall_num, arg1...arg6 as u64
/// * `reg_vals` - A pointer to a struct with all register values on call to 'syscall'.
///   RIP stored in RCX, RFLAGS stored in R11. This is used for fork().
///
/// # Safety
/// This function is unsafe as it must dereference `syscall` to get args
#[no_mangle]
pub unsafe extern "C" fn syscall_handler_impl(
    syscall: *const SyscallRegisters,
    reg_vals: *const ForkingRegisters,
) -> u64 {
    let syscall = unsafe { &*syscall };
    let reg_vals = unsafe { &*reg_vals };

    crate::debug!("SYS {}", syscall.number);

    with_current_pcb(|pcb| {
        //Msr::new(X2APIC_IA32_FS_BASE).write(pcb.fs_base);
        FsBase::write(VirtAddr::new(pcb.fs_base));
    });

    match syscall.number as u32 {
        SYSCALL_EXIT => {
            sys_exit(syscall.arg1 as i64, reg_vals);
            unreachable!("sys_exit does not return");
        }
        SYSCALL_PRINT => sys_print(syscall.arg1 as *const u8),
        // SYSCALL_NANOSLEEP => sys_nanosleep_64(syscall.arg1, reg_vals),
        SYSCALL_NANOSLEEP => block_on(sys_nanosleep(syscall.arg1), reg_vals),
        SYSCALL_RT_SIGPROCMASK => sys_rt_sigprocmask(
            syscall.arg1 as i32,
            ConstUserPtr::from(syscall.arg2),
            MutUserPtr::from(syscall.arg3),
            syscall.arg4 as usize,
        ),
        SYSCALL_GETPID => sys_getpid(),
        SYSCALL_GETTID => sys_gettid(),
        SYSCALL_TGKILL => sys_tgkill(
            syscall.arg1 as u32, // tgid (thread group ID / process ID)
            syscall.arg2 as u32, // tid (thread ID)
            syscall.arg3 as i32, // sig (signal number)
        ),
        SYSCALL_RT_SIGACTION => sys_rt_sigaction(
            syscall.arg1 as i32,
            syscall.arg2,
            syscall.arg3,
            syscall.arg4 as usize,
        ),
        // Filesystem syscalls
        SYSCALL_OPEN => block_on(
            sys_open(
                ConstUserPtr::from(syscall.arg1),
                syscall.arg2 as u32,
                syscall.arg3 as u16,
            ),
            reg_vals,
        ),
        SYSCALL_CREAT => block_on(
            sys_creat(ConstUserPtr::from(syscall.arg1), syscall.arg3 as u16),
            reg_vals,
        ),
        SYSCALL_FORK => sys_fork(reg_vals),
        SYSCALL_MMAP => block_on(
            sys_mmap(
                syscall.arg1,
                syscall.arg2,
                syscall.arg3,
                syscall.arg4,
                syscall.arg5 as i64,
                syscall.arg6,
            ),
            reg_vals,
        ),
        SYSCALL_WAIT => block_on(sys_wait(syscall.arg1 as u32), reg_vals),
        SYSCALL_SCHED_YIELD => block_on(sys_sched_yield(), reg_vals),
        SYSCALL_MUNMAP => sys_munmap(syscall.arg1, syscall.arg2),
        SYSCALL_MPROTECT => sys_mprotect(syscall.arg1, syscall.arg2, syscall.arg3),
        SYSCALL_UNAME => sys_uname(syscall.arg1 as *mut Utsname),
        SYSCALL_GETEUID => sys_geteuid(),
        SYSCALL_GETUID => sys_getuid(),
        SYSCALL_GETEGID => sys_getegid(),
        SYSCALL_GETGID => sys_getgid(),
        SYSCALL_ARCH_PRCTL => sys_arch_prctl(syscall.arg1 as i32, syscall.arg2),
        SYSCALL_READ => block_on(
            sys_read(
                syscall.arg1 as u32,
                syscall.arg2 as *mut u8,
                syscall.arg3 as usize,
            ),
            reg_vals,
        ),
        SYSCALL_WRITE => block_on(
            sys_write(
                syscall.arg1 as u32,
                syscall.arg2 as *mut u8,
                syscall.arg3 as usize,
            ),
            reg_vals,
        ),
        SYSCALL_WRITEV => block_on(
            sys_writev(
                syscall.arg1 as u32,
                syscall.arg2 as *const Iovec,
                syscall.arg3 as usize,
            ),
            reg_vals,
        ),
        SYSCALL_EXECVE => block_on(
            sys_exec(
                syscall.arg1 as *mut u8,
                syscall.arg2 as *mut *mut u8,
                syscall.arg3 as *mut *mut u8,
            ),
            reg_vals,
        ),
        SYSCALL_BRK => sys_brk(syscall.arg1),
        SYSCALL_SET_TID_ADDRESS => sys_set_tid_address(syscall.arg1 as *mut i32),
        _ => {
            panic!("Unknown syscall, {}", syscall.number);
        }
    }
}

/// # Safety
/// TODO
pub async unsafe fn sys_exec(path: *mut u8, argv: *mut *mut u8, envp: *mut *mut u8) -> u64 {
    if path.is_null() {
        return u64::MAX;
    }

    // Find string length by looking for null terminator
    let mut len = 0;
    unsafe {
        while *path.add(len) != 0 {
            len += 1;
        }
    }

    // Convert to string
    let bytes = unsafe { alloc::slice::from_raw_parts(path, len) };
    let pathname = match alloc::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return u64::MAX,
    };

    // build args
    let mut args = vec![];
    unsafe {
        let mut i = 0;
        loop {
            let ptr = *argv.add(i);
            if ptr.is_null() {
                break;
            }
            let mut l = 0;
            while *ptr.add(l) != 0 {
                l += 1;
            }
            let slice = slice::from_raw_parts(&*ptr, l);
            if let Ok(s) = str::from_utf8(slice) {
                args.push(s.to_string());
            }
            i += 1;
        }
    }

    serial_println!("NOT EXITING");

    // build env vars
    let mut envs = vec![];
    unsafe {
        let mut i = 0;
        loop {
            let ptr = *envp.add(i);
            if ptr.is_null() {
                break;
            }
            let mut l = 0;
            while *ptr.add(l) != 0 {
                l += 1;
            }
            let slice = slice::from_raw_parts(&*ptr, l);
            if let Ok(s) = str::from_utf8(slice) {
                envs.push(s.to_string());
            }
            i += 1;
        }
    }
    serial_println!("PATHNAME: {:#?}", pathname);
    serial_println!("CMD ARGS: {:#?}", args);
    serial_println!("ENV VARS: {:#?}", envs);
    schedule_kernel(
        async {
            let fs = FILESYSTEM.get().unwrap();
            let fd = {
                fs.lock()
                    .await
                    .open_file(
                        "/executables/hello",
                        OpenFlags::O_RDONLY | OpenFlags::O_WRONLY,
                    )
                    .await
            };
            // if fd.is_err() {
            //     serial_println!("Unknown command");
            //     return;
            // }
            serial_println!("RUNNING EXECUTABLE PLEASE HOLD");
            // At this point we assume a valid executable
            // TODO: check if it is actually executable with chmod mode
            let fd = fd.unwrap();
            let file = get_file(fd).unwrap();
            let file_len = {
                fs.lock()
                    .await
                    .filesystem
                    .lock()
                    .get_node(&file.lock().pathname)
                    .await
                    .unwrap()
                    .size()
            };
            sys_mmap(
                0x9000,
                align_up(file_len, PAGE_SIZE as u64),
                ProtFlags::PROT_EXEC.bits(),
                MmapFlags::MAP_FILE.bits(),
                fd as i64,
                0,
            )
            .await;

            serial_println!("Reading file...");

            let mut buffer = vec![0u8; file_len as usize];
            let bytes_read = {
                fs.lock()
                    .await
                    .read_file(fd, &mut buffer)
                    .await
                    .expect("Failed to read file")
            };

            let buf = &buffer[..bytes_read];

            serial_println!("Bytes read: {:#?}", bytes_read);

            let pid = create_process(buf, args, envs);
            schedule_process(pid);
            let _waiter = AwaitProcess::new(
                pid,
                get_runner_time(3_000_000_000),
                current_running_event().unwrap(),
            )
            .await;
        },
        3,
    );
    0
}

pub fn sys_brk(addr: u64) -> u64 {
    let old_brk = with_current_pcb(|pcb| pcb.brk);

    if addr == 0 {
        return old_brk;
    }

    // TODO error checking, for now just trust da user :)

    let new_brk = addr;
    let old_page =
        Page::<Size4KiB>::containing_address(VirtAddr::new(align_up(old_brk, PAGE_SIZE as u64)));
    let new_page =
        Page::<Size4KiB>::containing_address(VirtAddr::new(align_up(new_brk, PAGE_SIZE as u64)));
    with_current_pcb(|pcb| unsafe {
        let mut pt = pcb.create_mapper();

        for page in Page::range_inclusive(old_page, new_page) {
            let _frame = create_mapping(
                page,
                &mut pt,
                Some(
                    PageTableFlags::PRESENT
                        | PageTableFlags::USER_ACCESSIBLE
                        | PageTableFlags::WRITABLE,
                ),
            );
        }

        // TODO zero out pages (inclusive?)

        pcb.brk = new_brk;
    });

    new_brk
}

/// # Safety
/// TODO
pub async unsafe fn sys_read(fd: u32, buf: *mut u8, count: usize) -> u64 {
    if fd == 0 {
        let mut i = 0;
        while i < count {
            unsafe {
                match keyboard::try_read_event().await {
                    Some(event) => {
                        if let Some(c) = event_to_ascii(&event) {
                            *buf.add(i) = c;
                            i += 1;
                        }
                    }
                    None => break, // Exit early
                }
            }
        }
        i as u64
    } else {
        u64::MAX
    }
}

/// # Safety
/// TODO
pub async unsafe fn sys_write(fd: u32, buf: *const u8, count: usize) -> u64 {
    if fd == 1 {
        // STDOUT
        unsafe {
            let slice = core::slice::from_raw_parts(buf, count);
            serial_print!("{}", core::str::from_utf8_unchecked(slice));
        }
        count as u64
    } else {
        u64::MAX // Error
    }
}

#[repr(C)]
pub struct Iovec {
    iov_base: *mut u8,
    iov_len: usize,
}

/// # Safety
/// TODO
pub async unsafe fn sys_writev(fd: u32, iovec: *const Iovec, iovcnt: usize) -> u64 {
    if fd == 1 {
        // STDOUT
        unsafe {
            for _ in 0..iovcnt {
                let slice = core::slice::from_raw_parts((*iovec).iov_base, (*iovec).iov_len);
                serial_print!("{}", core::str::from_utf8_unchecked(slice));
            }
        }
        iovcnt as u64
    } else if fd == 2 {
        // STDERR
        unsafe {
            for _ in 0..iovcnt {
                let slice = core::slice::from_raw_parts((*iovec).iov_base, (*iovec).iov_len);
                serial_print!("{}", core::str::from_utf8_unchecked(slice));
            }
        }
        iovcnt as u64
    } else {
        u64::MAX // Error
    }
}

// Helper to convert keyboard events to ASCII
pub fn event_to_ascii(event: &keyboard::KeyboardEvent) -> Option<u8> {
    if event.state != KeyState::Down {
        return None;
    }

    match event.decoded {
        Some(DecodedKey::Unicode(c)) if c.is_ascii() => Some(c as u8),
        Some(DecodedKey::RawKey(KeyCode::Return)) => Some(b'\n'),
        Some(DecodedKey::RawKey(KeyCode::Backspace)) => Some(0x08),
        _ => None,
    }
}

pub fn sys_exit(code: i64, reg_vals: &ForkingRegisters) -> Option<u64> {
    // TODO handle hierarchy (parent processes), resources, threads, etc.

    // Used for testing
    if code == -1 {
        panic!("Exited with code -1");
    }

    let event: EventInfo = current_running_event_info();

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

        EXIT_CODES.lock().insert(event.pid, code);
        REGISTER_VALUES.lock().insert(event.pid, reg_vals.clone());
        PML4_FRAMES.lock().insert(event.pid, (*pcb).mm.pml4_frame);

        process_table.remove(&event.pid);
        ((*pcb).kernel_rsp, (*pcb).kernel_rip)
    };

    unsafe {
        // Restore kernel RSP + PC -> RIP from where it was stored in run/resume process
        core::arch::asm!(
            "mov rsp, {0}",
            "push {1}",
            "swapgs",
            "ret",
            in(reg) preemption_info.0,
            in(reg) preemption_info.1
        );
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
    send_eoi();

    0
}

/// Handle a nanosleep system call entered via syscall
/// Uses manually-created NonFlagRegisters struct to restore state
pub fn sys_nanosleep_64(nanos: u64, reg_vals: &ForkingRegisters) -> u64 {
    sleep_process_syscall(nanos, reg_vals);

    0
}

pub async fn sys_nanosleep(nanos: u64) -> u64 {
    unsafe {
        let event = current_running_event_info();
        let mut process_table = PROCESS_TABLE.write();

        let process = process_table
            .get_mut(&event.pid)
            .expect("Process not found");

        let pcb = process.pcb.get();

        (*pcb).state = ProcessState::Blocked;
    };

    nanosleep_current_event(nanos).unwrap().await;

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

pub async fn sys_sched_yield() -> u64 {
    yield_now().await;

    0
}

pub fn sys_geteuid() -> u64 {
    0
}

pub fn sys_getuid() -> u64 {
    0
}

pub fn sys_getegid() -> u64 {
    0
}

pub fn sys_getgid() -> u64 {
    0
}

const ARCH_SET_GS: i32 = 0x1001;
const ARCH_SET_FS: i32 = 0x1002;
const ARCH_GET_GS: i32 = 0x1003;
const ARCH_GET_FS: i32 = 0x1004;
const ARCH_CET_STATUS: i32 = 0x3001;
const ARCH_CET_DISABLE: i32 = 0x3002;
const ARCH_CET_LOCK: i32 = 0x3003;
const ARCH_CET_EXEC: i32 = 0x3004;
const ARCH_CET_ALLOC_SHSTK: i32 = 0x3005;
const ARCH_CET_PUSH_SHSTK: i32 = 0x3006;

/// Emulate arch_prctl(2)
pub fn sys_arch_prctl(code: i32, addr: u64) -> u64 {
    serial_println!("Code: {}", code);
    with_current_pcb(|pcb| {
        //Msr::new(X2APIC_IA32_FS_BASE).write(pcb.fs_base);
        FsBase::write(VirtAddr::new(pcb.fs_base));
    });

    // somewhere in kernel mode, AFTER you loaded the process’s FS_BASE
    let mut fs_word0: u64;

    unsafe {
        core::arch::asm!(
            "mov {out}, qword ptr fs:[0]",   // load 8-byte value at FS:0 → out
            out = out(reg) fs_word0,
            options(nostack, preserves_flags),
        );
    }

    serial_println!("value @ fs:0  = {:#018x}", fs_word0);

    let mut fs_plus8: u64;
    unsafe {
        core::arch::asm!(
            "mov {out}, qword ptr fs:[8]",
            out = out(reg) fs_plus8,
            options(nostack, preserves_flags),
        );
    }
    serial_println!("value @ fs:8  = {:#018x}", fs_plus8);

    // If fs:+8 is non-zero, fetch the two words in that table
    if fs_plus8 != 0 {
        let mut _dtv0: u64 = 0;
        let mut _dtv1: u64 = 0;
        unsafe {
            core::arch::asm!(
                "mov rax, {ptr}",
                "mov {o0}, qword ptr [rax]",
                "mov {o1}, qword ptr [rax + 8]",
                ptr = in(reg) fs_plus8,
                o0  = out(reg) _dtv0,
                o1  = out(reg) _dtv1,
                lateout("rax") _,
                options(nostack, preserves_flags),
            );
        }
        serial_println!("dtv[0]      = {:#018x}", _dtv0);
        serial_println!("dtv[1]      = {:#018x}", _dtv1);
    }

    match code {
        ARCH_SET_FS => {
            serial_println!("SET FS");
            // point %fs at user‐space TLS block
            unsafe { Msr::new(X2APIC_IA32_FS_BASE).write(addr) };
            0
        }
        ARCH_SET_GS => {
            serial_println!("SET GS");
            // point %gs at user‐space TLS block (if used)
            unsafe { Msr::new(X2APIC_IA32_FS_BASE).write(addr) };
            0
        }
        ARCH_GET_FS => {
            serial_println!("GET FS");
            // read current fs_base
            let fs = unsafe { Msr::new(X2APIC_IA32_FS_BASE).read() };
            // write it back into the user buffer
            let ptr = addr as *mut u64;
            unsafe { ptr.write_volatile(fs) };
            0
        }
        ARCH_GET_GS => {
            serial_println!("GET GS");
            let gs = unsafe { Msr::new(X2APIC_IA32_GSBASE).read() };
            let ptr = addr as *mut u64;
            unsafe { ptr.write_volatile(gs) };
            0
        }
        ARCH_CET_STATUS => 0,
        ARCH_CET_DISABLE => 0,
        ARCH_CET_LOCK => 0,
        ARCH_CET_EXEC => 0,
        ARCH_CET_ALLOC_SHSTK => 0,
        ARCH_CET_PUSH_SHSTK => 0,
        _ => {
            serial_println!("code unknown?");
            // unknown code
            0
        }
    }
}

#[repr(C)]
pub struct Utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
}

unsafe fn strcpy(dst: *mut u8, src: &str) {
    core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
    *(dst.add(src.len())) = b'\0';
}

// Unimplemented for now
// TODO fill ptr with OS information
pub fn sys_uname(_buf: *mut Utsname) -> u64 {
    unsafe {
        strcpy((*_buf).sysname.as_mut_ptr(), "TAOS");
        strcpy((*_buf).nodename.as_mut_ptr(), "localhost");
        strcpy((*_buf).release.as_mut_ptr(), "6.8.0");
        strcpy((*_buf).version.as_mut_ptr(), "#1 SMP PREEMPT_DYNAMIC");
        strcpy((*_buf).machine.as_mut_ptr(), "x86_64");
    }
    0
}

pub fn sys_rt_sigprocmask(
    _how: i32,
    _set: ConstUserPtr<u8>,
    _oldset: MutUserPtr<u8>,
    _sigsetsize: usize,
) -> u64 {
    // In a real implementation, this would manage the signal mask
    0
}

pub fn sys_getpid() -> u64 {
    // Return the pid of the current process
    with_current_pcb(|pcb| pcb.pid as u64)
}

pub fn sys_gettid() -> u64 {
    // In a single-threaded process, the thread ID is the same as the process ID
    with_current_pcb(|pcb| pcb.pid as u64)
}

pub fn sys_tgkill(_tgid: u32, _tid: u32, _sig: i32) -> u64 {
    // Minimal stub implementation
    // In a real implementation, this would:
    // 1. Validate that tgid is a valid process ID
    // 2. Validate that tid is a valid thread ID within that process
    // 3. Check if the caller has permission to send the signal
    // 4. Deliver the signal to the specified thread
    // Return 0 for success
    0
}

pub fn sys_rt_sigaction(_signum: i32, _act_ptr: u64, _oldact_ptr: u64, _sigsetsize: usize) -> u64 {
    // Minimal stub implementation
    // In a real implementation, this would:
    // 1. Validate the signal number
    // 2. Set up a new handler if 'act' is not null
    // 3. Return the old handler if 'oldact' is not null
    // 4. Validate sigsetsize

    0
}

pub fn sys_set_tid_address(_tidptr: *mut i32) -> u64 {
    0
}