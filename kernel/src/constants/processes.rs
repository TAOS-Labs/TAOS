pub const TEST_SIMPLE_STACK_ACCESS: &[u8] =
    include_bytes!("../processes/debug_binaries/test_simple_stack_access");

pub const TEST_64_SLEEP: &[u8] = include_bytes!("../processes/debug_binaries/64_sleep");

pub const TEST_64_SIMPLE_EXIT: &[u8] =
    include_bytes!("../processes/debug_binaries/test_64_simple_exit");
pub const TEST_64_PRINT_EXIT: &[u8] =
    include_bytes!("../processes/debug_binaries/test_64_print_exit");
pub const TEST_64_FORK_EXIT: &[u8] =
    include_bytes!("../processes/debug_binaries/test_64_fork_simple");
pub const TEST_64_FORK_COW: &[u8] = include_bytes!("../processes/debug_binaries/test_64_fork_cow");
pub const TEST_MMAP_ALLOC:  &[u8] = include_bytes!("../processes/debug_binaries/test_mmap_alloc");

pub const SYSCALL_32BIT_TEST: &[u8] =
    include_bytes!("../processes/debug_binaries/test_asm_32bit_syscall");
pub const SYSCALL_64BIT_TEST: &[u8] =
    include_bytes!("../processes/debug_binaries/test_syscall_instruction");
pub const SYSCALL_THEN_LOOP: &[u8] =
    include_bytes!("../processes/debug_binaries/syscall_and_args_loop");
pub const SYSCALL_PRINT: &[u8] = include_bytes!("../processes/debug_binaries/test_print");

pub const PRINT_AND_SLEEP: &[u8] = include_bytes!("../processes/debug_binaries/sleep");
pub const PRINT_EXIT: &[u8] = include_bytes!("../processes/debug_binaries/print_exit");
pub const MMAP_ANON_SIMPLE: &[u8] = include_bytes!("../processes/debug_binaries/mmap_anon_simple");
pub const FORK_SIMPLE: &[u8] = include_bytes!("../processes/debug_binaries/fork_simple");

// tests
pub const TEST_SIMPLE_PROCESS: &[u8] =
    include_bytes!("../processes/test_binaries/test_simple_process");
pub const TEST_EXIT_CODE: &[u8] = include_bytes!("../processes/test_binaries/test_exit_code");
pub const TEST_PRINT_EXIT: &[u8] = include_bytes!("../processes/test_binaries/test_print_exit");
pub const TEST_WAIT: &[u8] = include_bytes!("../processes/test_binaries/test_wait");
pub const TEST_FORK_COW: &[u8] = include_bytes!("../processes/test_binaries/test_fork_cow");

pub const STACK_START: u64 = 0x7000_0000_0000;
pub const MAX_FILES: usize = 1024;
pub const PROCESS_NANOS: u64 = 50_000_000;
pub const STACK_SIZE: usize = 2 * 4096; // 2 pages for the stack

pub const PROCESS_TIMESLICE: u64 = 50_000_000; // 50 ms, to change later
