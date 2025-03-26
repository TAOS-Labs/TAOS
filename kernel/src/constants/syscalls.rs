//! Syscall numbers

pub const SYSCALL_NANOSLEEP: u32 = 35;
pub const SYSCALL_EXIT: u32 = 60;

// Move to above 1000 (reserve for custom syscalls)

pub const SYSCALL_MOUNT_P9: u32 = 1000;
pub const SYSCALL_UNMOUNT_P9: u32 = 1001;
pub const SYSCALL_BIND_P9: u32 = 1002;

pub const SYSCALL_REGISTER_MSG_HANDLER: u32 = 1003;
pub const SYSCALL_UNREGISTER_MSG_HANDLER: u32 = 1004;

// currently occupying sys_close (will thus need to replace soon)
pub const SYSCALL_PRINT: u32 = 3;
