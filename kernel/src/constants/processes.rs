pub const TEST_SYSCALL_PRINT: &[u8] = include_bytes!("../processes/test_binaries/test_print");
pub const SYSCALL_MMAP_MEMORY: &[u8] = include_bytes!("../processes/test_binaries/mmap");
pub const RAND_REGS_EXIT: &[u8] = include_bytes!("../processes/test_binaries/rand_regs_exit");
pub const PRINT_EXIT: &[u8] = include_bytes!("../processes/test_binaries/print_exit");
pub const PRINT_PRINT_EXIT: &[u8] = include_bytes!("../processes/test_binaries/print_print_exit");
pub const MMAP_ANON_SIMPLE: &[u8] = include_bytes!("../processes/test_binaries/mmap_anon_simple");
pub const MMAP_ANON_SIMPLE_TEST: &[u8] =
    include_bytes!("../processes/test_binaries/mmap_anon_simple_test");
pub const FORK_SIMPLE: &[u8] = include_bytes!("../processes/test_binaries/fork_simple");

pub const STACK_START: u64 = 0x7000_0000_0000;
pub const STACK_SIZE: usize = 2 * 4096; // 2 pages for the stack
pub const MAX_FILES: usize = 4;
pub const PROCESS_NANOS: u64 = 50_000_000;
