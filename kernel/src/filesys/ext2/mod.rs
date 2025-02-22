pub mod allocator;
pub mod block_io;
pub mod cache;
pub mod filesystem;
pub mod ide;
pub mod node;
pub mod structures;

/// Get current Unix timestamp
pub fn get_current_time() -> u32 {
    // For now, return a dummy
    1234567890
}
