//! Syscall numbers

pub const SYSCALL_NANOSLEEP: u32 = 35;
pub const SYSCALL_EXIT: u32 = 60;

// TODO move to above 1000 (reserve for custom syscalls)
// currently occupying sys_close (will thus need to replace soon)
pub const SYSCALL_PRINT: u32 = 3; 
