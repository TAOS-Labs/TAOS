//! x2APIC configuration constants.

/// CPU timer frequency in Hertz.
/// Determines how often timer interrupts occur.
pub const CPU_FREQUENCY: u32 = 100;

/// Milliseconds per one timer tick
pub const MS_PER_TICK: u32 = 1000 / CPU_FREQUENCY;

/// Nanoseconds per one timer tick
pub const NS_PER_TICK: u64 = 1_000_000_000 / CPU_FREQUENCY as u64;
