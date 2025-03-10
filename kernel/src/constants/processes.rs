pub const PRINT_EXIT: &[u8] = include_bytes!("../processes/test_binaries/print_exit");
pub const MMAP_ANON_SIMPLE: &[u8] = include_bytes!("../processes/test_binaries/mmap_anon_simple");
pub const FORK_SIMPLE: &[u8] = include_bytes!("../processes/test_binaries/fork_simple");

pub const TEST_SIMPLE_STACK_ACCESS: &[u8] =
    include_bytes!("../processes/test_binaries/test_simple_stack_access");

pub const TEST_64_SLEEP: &[u8] = include_bytes!("../processes/test_binaries/64_sleep");

// SYSCALL TESTING BINARIES
pub const TEST_64_SIMPLE_EXIT: &[u8] =
    include_bytes!("../processes/test_binaries/test_64_simple_exit");
pub const TEST_64_PRINT_EXIT: &[u8] =
    include_bytes!("../processes/test_binaries/test_64_print_exit");
pub const TEST_64_FORK_EXIT: &[u8] =
    include_bytes!("../processes/test_binaries/test_64_fork_simple");
pub const TEST_64_FORK_COW: &[u8] = include_bytes!("../processes/test_binaries/test_64_fork_cow");

pub const STACK_START: u64 = 0x7000_0000_0000;
pub const STACK_SIZE: usize = 2 * 4096; // 2 pages for the stack
pub const MAX_FILES: usize = 4;
pub const PROCESS_NANOS: u64 = 50_000_000;
pub const INFINITE_LOOP: &[u8] = include_bytes!("../processes/test_binaries/rand_regs");
pub const LONG_LOOP: &[u8] = include_bytes!("../processes/test_binaries/long_loop_print");
pub const SYSCALL_32BIT_TEST: &[u8] =
    include_bytes!("../processes/test_binaries/test_asm_32bit_syscall");
pub const SYSCALL_64BIT_TEST: &[u8] =
    include_bytes!("../processes/test_binaries/test_syscall_instruction");
pub const SYSCALL_THEN_LOOP: &[u8] =
    include_bytes!("../processes/test_binaries/syscall_and_args_loop");
pub const SYSCALL_PRINT: &[u8] = include_bytes!("../processes/test_binaries/test_print");
pub const PRINT_AND_SLEEP: &[u8] = include_bytes!("../processes/test_binaries/sleep");

pub const STACK_START: u64 = 0x7000_0000_0000;
pub const STACK_SIZE: usize = 2 * 4096; // 2 pages for the stack

pub const PROCESS_NANOS: u64 = 50_000_000; // 50 ms, to change later
