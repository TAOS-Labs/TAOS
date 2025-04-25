//! Syscall numbers

pub const SYSCALL_EXIT: u32 = 60;
pub const SYSCALL_NANOSLEEP: u32 = 35;
pub const SYSCALL_PRINT: u32 = 3;
pub const SYSCALL_MMAP: u32 = 4;
pub const SYSCALL_MPROTECT: u32 = 10;
pub const SYSCALL_MUNMAP: u32 = 11;
pub const SYSCALL_FORK: u32 = 5;
pub const SYSCALL_WAIT: u32 = 6;
pub const SYSCALL_SOCKET: u32 = 41;
pub const SYSCALL_BIND: u32 = 49;
pub const SYSCALL_CONNECT: u32 = 42;

// Mmap
pub const START_MMAP_ADDRESS: u64 = 0x0900_0000_0000;
