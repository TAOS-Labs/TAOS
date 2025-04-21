//! Process related constants

// Binaries used for tests
pub const PRINT_EXIT: &[u8] = include_bytes!("../processes/test_binaries/print_exit");

pub const FORK_SIMPLE: &[u8] = include_bytes!("../processes/test_binaries/fork_simple");

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

// Virtual memory address for the stack
pub const STACK_START: u64 = 0x7000_0000_0000;

// Maximum number of files for the process control block's file descriptor table
// if this number is big clone fails
pub const MAX_FILES: usize = 128;

// Number of signals - Linux handles 32 so we are just going to max support that many
pub const NUM_SIGNALS: usize = 32;

// Pre-emption time
pub const PROCESS_NANOS: u64 = 50_000_000;

// Size of the process stack - 2 pages
pub const STACK_SIZE: usize = 2 * 4096;

pub const PROCESS_TIMESLICE: u64 = 50_000_000; // 50 ms, to change later
