//! Global Descriptor Table and stack configuration.

/// Index in the Interrupt Stack Table (IST) for handling double faults.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Size of each IST stack in bytes.
/// Set to 16KB (4 pages) to handle deep call stacks during faults.
pub const IST_STACK_SIZE: usize = 4096 * 4;
pub const RING0_STACK_SIZE: usize = 4096 * 4;
