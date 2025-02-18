//! Interrupt Descriptor Table configuration.

/// Vector number assigned to the timer interrupt.
pub const TIMER_VECTOR: u8 = 32;
pub const SYSCALL_HANDLER: u8 = 0x80;
