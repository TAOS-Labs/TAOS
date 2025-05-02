//! Interrupt Descriptor Table configuration.

/// Vector number assigned to the timer interrupt.
pub const TIMER_VECTOR: u8 = 32;
pub const SYSCALL_HANDLER: u8 = 0x80;
pub const KEYBOARD_VECTOR: u8 = 33;
pub const MOUSE_VECTOR: u8 = 44;
pub const HDA_VECTOR: u8 = 45;

pub const TLB_SHOOTDOWN_VECTOR: u8 = 33;
