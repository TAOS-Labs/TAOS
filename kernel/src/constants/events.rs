//! Event system configuration constants.

/// Maximum number of events that can be queued in the system.
pub const MAX_EVENTS: usize = 256;

/// Number of priority levels for event processing.
/// Higher priority events are processed before lower priority ones.
pub const NUM_EVENT_PRIORITIES: usize = 4;

pub const PRIORITY_INC_DELAY: u64 = 5; // TODO try different values
