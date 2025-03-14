//! System-wide constants and hardware-specific values.

/// Maximum number of CPU cores supported by the kernel.
pub const MAX_CORES: usize = 2;

pub mod devices;
pub mod events;
pub mod gdt;
pub mod idt;
pub mod memory;
pub mod ports;
pub mod processes;
pub mod syscalls;
pub mod x2apic;
