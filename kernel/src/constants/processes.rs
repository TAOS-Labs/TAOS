pub const PRINT_EXIT: &[u8] = include_bytes!("../processes/test_binaries/print_exit");
pub const MMAP_ANON_SIMPLE: &[u8] = include_bytes!("../processes/test_binaries/mmap_anon_simple");
pub const FORK_SIMPLE: &[u8] = include_bytes!("../processes/test_binaries/fork_simple");

// tests
pub const TEST_SIMPLE_PROCESS: &[u8] =
    include_bytes!("../processes/test_binaries/test_simple_process");
pub const TEST_EXIT_CODE: &[u8] = include_bytes!("../processes/test_binaries/test_exit_code");
pub const TEST_PRINT_EXIT: &[u8] = include_bytes!("../processes/test_binaries/test_print_exit");
pub const TEST_WAIT: &[u8] = include_bytes!("../processes/test_binaries/test_wait");
pub const TEST_FORK_COW: &[u8] = include_bytes!("../processes/test_binaries/test_fork_cow");
pub const TEST_MMAP_ANON_SHARED: &[u8] =
    include_bytes!("../processes/test_binaries/test_mmap_anon_shared");
pub const TEST_MMAP_CHILD_WRITES: &[u8] =
    include_bytes!("../processes/test_binaries/test_mmap_child_writes");
pub const TEST_MPROTECT_CHILD_WRITES: &[u8] =
    include_bytes!("../processes/test_binaries/test_mprotect_child_writes");

pub const STACK_START: u64 = 0x7000_0000_0000;
// if this number is big clone fails
pub const MAX_FILES: usize = 128;
pub const PROCESS_NANOS: u64 = 50_000_000;
pub const STACK_SIZE: usize = 2 * 4096; // 2 pages for the stack

pub const PROCESS_TIMESLICE: u64 = 50_000_000; // 50 ms, to change later
