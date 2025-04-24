//! Syscall numbers

pub const SYSCALL_EXIT: u32 = 60;
pub const SYSCALL_NANOSLEEP: u32 = 35;

pub const SYSCALL_PRINT: u32 = 1003; 

pub const SYSCALL_READ: u32 = 0;
pub const SYSCALL_WRITE: u32 = 1;
pub const SYSCALL_OPEN: u32 = 2;
pub const SYSCALL_CLOSE: u32 = 3;

pub const SYSCALL_ACCESS: u32 = 21;

pub const SYSCALL_SCHED_YIELD: u32 = 24;

pub const SYSCALL_CREAT: u32 = 85;

pub const SYSCALL_FUTEX: u32 = 202;
pub const SYSCALL_OPENAT: u32 = 257;

pub const SYSCALL_GETRANDOM: u32 = 318;

pub const SYSCALL_MMAP: u32 = 4;
pub const SYSCALL_MPROTECT: u32 = 10;
pub const SYSCALL_MUNMAP: u32 = 11;
pub const SYSCALL_FORK: u32 = 5;
pub const SYSCALL_WAIT: u32 = 6;

pub const SYSCALL_GETUID: u32 = 102;
pub const SYSCALL_GETEUID: u32 = 107;
pub const SYSCALL_GETGID: u32 = 104;
pub const SYSCALL_GETEGID: u32 = 108;
pub const SYSCALL_ARCH_PRCTL: u32 = 158;

// Mmap
pub const START_MMAP_ADDRESS: u64 = 0x0900_0000_0000;
