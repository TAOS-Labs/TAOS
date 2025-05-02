//! Process related constants

// Binaries used for tests
pub const FORK_SIMPLE: &[u8] = include_bytes!("../processes/test_binaries/fork_simple");

pub const TEST_SIMPLE_PROCESS: &[u8] =
    include_bytes!("../processes/test_binaries/test_simple_process");

pub const TEST_EXIT_CODE: &[u8] = include_bytes!("../processes/test_binaries/test_exit_code");

pub const TEST_PRINT_EXIT: &[u8] = include_bytes!("../processes/test_binaries/test_print_exit");

pub const TEST_WAIT: &[u8] = include_bytes!("../processes/test_binaries/test_wait");

pub const TEST_SLEEP: &[u8] = include_bytes!("../processes/test_binaries/sleep");

pub const TEST_FORK_COW: &[u8] = include_bytes!("../processes/test_binaries/test_fork_cow");

pub const TEST_MMAP_ANON_SHARED: &[u8] =
    include_bytes!("../processes/test_binaries/test_mmap_anon_shared");

pub const TEST_MMAP_CHILD_WRITES: &[u8] =
    include_bytes!("../processes/test_binaries/test_mmap_child_writes");

pub const TEST_MPROTECT_CHILD_WRITES: &[u8] =
    include_bytes!("../processes/test_binaries/test_mprotect_child_writes");

// Virtual memory address for the stack
pub const STACK_END: u64 = 0x7FFF_FFFF_0000;

// User Heaps
pub const USR_HEAP_START: u64 = 0x5_000_0000;

// Maximum number of files for the process control block's file descriptor table
// if this number is big clone fails
pub const MAX_FILES: usize = 128;

// Pre-emption time
pub const PROCESS_NANOS: u64 = 50_000_000;

// Size of the process stack - 2 pages
pub const STACK_SIZE: usize = 10 * 4096;
pub const STACK_MAX_SIZE: usize = (STACK_END - 0x7000_0000_0000) as usize;

pub const PROCESS_TIMESLICE: u64 = 50_000_000; // 50 ms, to change later
