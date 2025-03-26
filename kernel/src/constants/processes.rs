pub const SYSCALL_32BIT_TEST: &[u8] =
    include_bytes!("../processes/test_binaries/test_asm_32bit_syscall");
pub const SYSCALL_64BIT_TEST: &[u8] =
    include_bytes!("../processes/test_binaries/test_syscall_instruction");
pub const SYSCALL_EXIT_TEST: &[u8] = include_bytes!("../processes/test_binaries/exit");
pub const SYSCALL_THEN_LOOP: &[u8] =
    include_bytes!("../processes/test_binaries/syscall_and_args_loop");
pub const SYSCALL_PRINT: &[u8] = include_bytes!("../processes/test_binaries/test_print");

pub const PRINT_AND_SLEEP: &[u8] = include_bytes!("../processes/test_binaries/sleep");
pub const LONG_LOOP: &[u8] = include_bytes!("../processes/test_binaries/long_loop_print");

pub const STACK_START: u64 = 0x7000_0000_0000;
pub const STACK_SIZE: usize = 2 * 4096; // 2 pages for the stack

pub const PROCESS_TIMESLICE: u64 = 50_000_000; // 50 ms, to change later

pub const FS_PID: u64 = 1;