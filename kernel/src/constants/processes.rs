pub const BINARY: &[u8] = include_bytes!("../processes/test_binaries/rand_regs");

pub const STACK_START: u64 = 0x7000_0000_0000;
pub const STACK_SIZE: usize = 2 * 4096; // 2 pages for the stack
