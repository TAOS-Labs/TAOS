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

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use crate::devices::sd_card::SD_CARD;

    use super::filesystem::Ext2;

    const MEDIUM_FILE: &[u8] = include_bytes!("../../../../resources/fonts/Comfortaa-Regular.ttf");

    // Size and layout tests
    #[test_case]
    async fn fat_test_all() {
        let sd_card_lock = SD_CARD.lock();
        let sd_card = sd_card_lock.clone().unwrap();
        let sd_arc = Arc::new(sd_card);
        let fs = Ext2::new(sd_arc).await.unwrap();
        fs.mount().await.unwrap();
        let file = fs.read_file("/fonts/Comfortaa-Regular.ttf").await.unwrap();
        assert!(file == MEDIUM_FILE);
    }
}
