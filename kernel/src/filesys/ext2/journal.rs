/// journal.rs
///
/// This file implements the main journal functionality for the ext2 filesystem.
/// The journal provides write-ahead logging to ensure filesystem integrity
/// in case of crashes or unexpected shutdowns.
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    mem::size_of,
    sync::atomic::{AtomicU32, Ordering},
};
use spin::{Mutex, RwLock};

use super::{
    allocator::Allocator,
    block_io::BlockIO,
    cache::{block::CachedBlock, Cache},
    journal_structures::{
        JournalBlockEntry, JournalBlockFlags, JournalBlockInfo, JournalBlockType,
        JournalCommitBlock, JournalDescriptorBlock, JournalError, JournalResult, JournalSuperblock,
        TransactionState, JOURNAL_MAGIC,
    },
    structures::Superblock,
};

/// Main journal structure
pub struct Journal {
    /// The underlying block device
    device: Arc<dyn BlockIO>,
    /// Journal superblock
    superblock: Mutex<JournalSuperblock>,
    /// Filesystem superblock reference
    fs_superblock: Arc<RwLock<Superblock>>,
    /// Cache for reading/writing journal blocks
    block_cache: Arc<Mutex<Box<dyn Cache<u32, CachedBlock>>>>,
    /// Current transaction state
    transaction_state: Mutex<TransactionState>,
    /// Current transaction sequence number (atomic)
    current_sequence: AtomicU32,
    /// Current transaction blocks
    transaction_blocks: Mutex<Vec<JournalBlockInfo>>,
    /// Journal location (first block)
    journal_start_block: u32,
    /// Maximum blocks in a transaction
    max_transaction_blocks: u32,
    /// Checkpoint mutex to prevent concurrent checkpoints
    checkpoint_lock: Mutex<()>,
    /// Block size
    block_size: u32,
    /// Filesystem block count (for sanity checks)
    fs_block_count: u32,
    /// Allocator reference for recovery
    allocator: Arc<Mutex<Allocator>>,
    /// Transaction-level lock
    transaction_lock: RwLock<()>,
}

impl Journal {
    /// Create a new journal
    pub fn new(
        device: Arc<dyn BlockIO>,
        fs_superblock: Arc<RwLock<Superblock>>,
        block_cache: Arc<Mutex<Box<dyn Cache<u32, CachedBlock>>>>,
        journal_start_block: u32,
        journal_size_blocks: u32,
        allocator: Arc<Mutex<Allocator>>,
    ) -> Self {
        let block_size = fs_superblock.read().block_size();
        let fs_block_count = fs_superblock.read().num_blocks;

        let superblock = JournalSuperblock::new(journal_size_blocks);

        Self {
            device,
            superblock: Mutex::new(superblock),
            fs_superblock,
            block_cache,
            transaction_state: Mutex::new(TransactionState::None),
            current_sequence: AtomicU32::new(1),
            transaction_blocks: Mutex::new(Vec::new()),
            journal_start_block,
            max_transaction_blocks: 1024, // Default, will be updated from superblock
            checkpoint_lock: Mutex::new(()),
            block_size,
            fs_block_count,
            allocator,
            transaction_lock: RwLock::new(()),
        }
    }

    // Creates a new journal on disk
    pub async fn format(&self) -> JournalResult<()> {
        let _transaction_guard = self.transaction_lock.write();

        let mut superblock = self.superblock.lock();

        *superblock = JournalSuperblock::new(superblock.journal_blocks);
        superblock.update_checksum();

        let journal_block = self.map_journal_block(0);
        let mut buffer = vec![0u8; self.block_size as usize];

        unsafe {
            let src_ptr = &*superblock as *const JournalSuperblock as *const u8;
            let dst_ptr = buffer.as_mut_ptr();
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size_of::<JournalSuperblock>());
        }

        let journal_blocks = superblock.journal_blocks;
        self.device.write_block(journal_block, &buffer).await?;

        drop(superblock);

        buffer.fill(0);

        for i in 1..journal_blocks {
            self.device
                .write_block(self.map_journal_block(i), &buffer)
                .await?;
        }

        Ok(())
    }

    /// Load the journal from disk, checking for consistency
    pub async fn load(&mut self) -> JournalResult<bool> {
        let _transaction_guard = self.transaction_lock.write();

        let journal_block = self.map_journal_block(0);
        let mut buffer = vec![0u8; self.block_size as usize];

        self.device.read_block(journal_block, &mut buffer).await?;

        let superblock = unsafe {
            let src_ptr = buffer.as_ptr();
            let mut sb = JournalSuperblock::new(0);
            let dst_ptr = &mut sb as *mut JournalSuperblock as *mut u8;
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size_of::<JournalSuperblock>());
            sb
        };

        if !superblock.is_valid() {
            return Err(JournalError::InvalidSuperblock);
        }

        // Stored checksum should match calculated
        let stored_checksum = superblock.checksum;
        let mut sb_copy = superblock.clone();
        sb_copy.checksum = 0;
        let calculated_checksum = sb_copy.calculate_checksum();

        if stored_checksum != calculated_checksum {
            return Err(JournalError::ChecksumMismatch);
        }

        let sequence = superblock.sequence;
        let max_transaction = superblock.max_transaction;
        let start_sequence = superblock.start_sequence;

        {
            let mut sb_lock = self.superblock.lock();
            *sb_lock = superblock;
        }

        self.current_sequence.store(sequence, Ordering::SeqCst);
        self.max_transaction_blocks = max_transaction;

        let needs_recovery = start_sequence < sequence;

        Ok(needs_recovery)
    }

    /// Start a new transaction
    pub async fn start_transaction(&self) -> JournalResult<()> {
        let _transaction_guard = self.transaction_lock.write();

        let mut state = self.transaction_state.lock();

        if *state != TransactionState::None {
            return Err(JournalError::AlreadyInTransaction);
        }

        *state = TransactionState::Running;

        let mut blocks = self.transaction_blocks.lock();
        blocks.clear();

        Ok(())
    }

    /// Add a block to the current transaction
    pub async fn journal_block(&self, block_number: u32, data: &[u8]) -> JournalResult<()> {
        let _transaction_guard = self.transaction_lock.read();

        if block_number >= self.fs_block_count {
            return Err(JournalError::InvalidBlock);
        }

        let state = self.transaction_state.lock();
        if *state != TransactionState::Running {
            return Err(JournalError::NotInTransaction);
        }
        drop(state);

        let journal_block_device;
        let journal_block_relative;
        {
            let mut blocks = self.transaction_blocks.lock();
            if blocks.iter().any(|b| b.fs_block == block_number) {
                return Ok(());
            }

            if blocks.len() >= self.max_transaction_blocks as usize {
                return Err(JournalError::TransactionTooLarge);
            }

            let block_offset = blocks.len() as u32 + 1;

            journal_block_device = self.allocate_journal_block(block_offset)?;

            let superblock = self.superblock.lock();
            journal_block_relative =
                (superblock.first_transaction + block_offset) % superblock.journal_blocks;
            drop(superblock);

            blocks.push(JournalBlockInfo {
                fs_block: block_number,
                journal_block: journal_block_relative,
                flags: JournalBlockFlags::empty(),
            });
        }

        self.device.write_block(journal_block_device, data).await?;

        Ok(())
    }

    /// Commit the current transaction
    pub async fn commit_transaction(&self) -> JournalResult<()> {
        let _transaction_guard = self.transaction_lock.write();

        let mut state = self.transaction_state.lock();
        if *state != TransactionState::Running {
            return Err(JournalError::NotInTransaction);
        }

        *state = TransactionState::Committing;

        let sequence = self.current_sequence.load(Ordering::SeqCst);

        let blocks = self.transaction_blocks.lock();
        let is_empty = blocks.is_empty();

        if is_empty {
            *state = TransactionState::None;
            return Ok(());
        }

        let blocks_copy = blocks.clone();
        drop(blocks);

        let desc_journal_block = self.allocate_journal_block(0)?;
        self.write_descriptor_block(desc_journal_block, &blocks_copy, sequence)
            .await?;

        let commit_journal_block = self.allocate_journal_block(blocks_copy.len() as u32 + 2)?;
        self.write_commit_block(commit_journal_block, sequence)
            .await?;

        for block_info in blocks_copy.iter() {
            let mut buffer = vec![0u8; self.block_size as usize];

            self.device
                .read_block(
                    self.map_journal_block(block_info.journal_block),
                    &mut buffer,
                )
                .await?;

            self.device
                .write_block(block_info.fs_block as u64, &buffer)
                .await?;
        }

        let mut superblock = self.superblock.lock();
        superblock.sequence = sequence + 1;

        let used_blocks = blocks_copy.len() as u32 + 3;
        superblock.first_transaction =
            (superblock.first_transaction + used_blocks) % superblock.journal_blocks;

        superblock.update_checksum();

        let need_checkpoint = blocks_copy.len() > (superblock.journal_blocks as usize / 2);

        self.write_superblock_with_lock(&superblock).await?;
        drop(superblock);

        self.current_sequence.fetch_add(1, Ordering::SeqCst);

        *state = TransactionState::None;
        drop(state);

        drop(_transaction_guard);

        if need_checkpoint {
            self.checkpoint().await?;
        }

        Ok(())
    }

    /// Abort the current transaction
    pub async fn abort_transaction(&self) -> JournalResult<()> {
        let _transaction_guard = self.transaction_lock.write();

        let mut state = self.transaction_state.lock();
        if *state != TransactionState::Running {
            return Err(JournalError::NotInTransaction);
        }

        *state = TransactionState::None;

        let mut blocks = self.transaction_blocks.lock();
        blocks.clear();

        Ok(())
    }

    /// Recover the journal after a crash
    pub async fn recover(&self) -> JournalResult<()> {
        let _transaction_guard = self.transaction_lock.write();

        let _guard = self.checkpoint_lock.lock();

        let (start_seq, end_seq) = {
            let superblock = self.superblock.lock();
            (superblock.start_sequence, superblock.sequence)
        };

        if start_seq >= end_seq {
            return Ok(());
        }

        for seq in start_seq..end_seq {
            self.replay_transaction(seq).await?;
        }

        {
            let mut superblock = self.superblock.lock();
            superblock.start_sequence = end_seq;
            superblock.update_checksum();
            self.write_superblock_with_lock(&superblock).await?;
        }

        Ok(())
    }

    /// Clean up the journal by removing completed transactions
    pub async fn checkpoint(&self) -> JournalResult<()> {
        let _transaction_guard = self.transaction_lock.read();

        let _guard = self.checkpoint_lock.lock();

        let needs_update = {
            let superblock = self.superblock.lock();
            superblock.start_sequence < superblock.sequence
        };

        if needs_update {
            let mut superblock = self.superblock.lock();
            superblock.start_sequence = superblock.sequence;
            superblock.update_checksum();
            self.write_superblock_with_lock(&superblock).await?;
        }

        Ok(())
    }

    /// Map a journal block number to a device block number
    fn map_journal_block(&self, journal_block: u32) -> u64 {
        (self.journal_start_block + journal_block) as u64
    }

    /// Allocate a block in the journal
    fn allocate_journal_block(&self, block_offset: u32) -> JournalResult<u64> {
        let superblock = self.superblock.lock();
        let journal_blocks = superblock.journal_blocks;
        let first_transaction = superblock.first_transaction;

        let sequence = self.current_sequence.load(Ordering::SeqCst);

        // Calculate the actual block number in the journal
        let journal_block_num = (first_transaction + block_offset) % journal_blocks;

        if superblock.start_sequence < sequence {
            // Calculate the "tail" of the journal (oldest block we can't overwrite)
            let tail_block = first_transaction;

            // Check if our allocation would wrap around and catch up with the tail
            let would_overwrite = if first_transaction <= tail_block {
                // Regular case
                journal_block_num >= tail_block && journal_block_num < first_transaction
            } else {
                // Wrap-around case
                journal_block_num >= tail_block || journal_block_num < first_transaction
            };

            if would_overwrite {
                return Err(JournalError::JournalFull);
            }
        }

        Ok(self.map_journal_block(journal_block_num))
    }

    /// Write the journal superblock to disk
    async fn write_superblock(&self) -> JournalResult<()> {
        let superblock = self.superblock.lock();
        self.write_superblock_with_lock(&superblock).await
    }

    /// Write the superblock to disk while already holding the lock
    async fn write_superblock_with_lock(
        &self,
        superblock: &JournalSuperblock,
    ) -> JournalResult<()> {
        let journal_block = self.map_journal_block(0);
        let mut buffer = vec![0u8; self.block_size as usize];

        unsafe {
            let src_ptr = superblock as *const JournalSuperblock as *const u8;
            let dst_ptr = buffer.as_mut_ptr();
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size_of::<JournalSuperblock>());
        }

        self.device.write_block(journal_block, &buffer).await?;

        Ok(())
    }

    /// Write a descriptor block
    async fn write_descriptor_block(
        &self,
        journal_block: u64,
        blocks: &[JournalBlockInfo],
        sequence: u32,
    ) -> JournalResult<()> {
        let mut buffer = vec![0u8; self.block_size as usize];

        let mut descriptor = JournalDescriptorBlock::new(sequence, blocks.len() as u32);

        for block_info in blocks {
            descriptor.entries.push(JournalBlockEntry {
                block_number: block_info.fs_block,
                flags: block_info.flags.bits(),
            });
        }

        descriptor.serialize(&mut buffer);

        self.device.write_block(journal_block, &buffer).await?;

        Ok(())
    }

    /// Write a commit block
    async fn write_commit_block(&self, journal_block: u64, sequence: u32) -> JournalResult<()> {
        let mut buffer = vec![0u8; self.block_size as usize];

        let commit = JournalCommitBlock {
            magic: JOURNAL_MAGIC,
            block_type: JournalBlockType::Commit as u32,
            sequence,
            checksum: 0, // TODO: Calculate checksum
        };

        unsafe {
            let src_ptr = &commit as *const JournalCommitBlock as *const u8;
            let dst_ptr = buffer.as_mut_ptr();
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size_of::<JournalCommitBlock>());
        }

        self.device.write_block(journal_block, &buffer).await?;

        Ok(())
    }

    /// Replay a single transaction during recovery
    async fn replay_transaction(&self, sequence: u32) -> JournalResult<()> {
        let (journal_blocks, first_transaction) = {
            let superblock = self.superblock.lock();
            (superblock.journal_blocks, superblock.first_transaction)
        };

        let mut current_block = first_transaction;
        let mut blocks_to_replay = Vec::new();
        let mut total_blocks_in_transaction = 0;

        for _ in 0..journal_blocks {
            let journal_block = self.map_journal_block(current_block);
            let mut buffer = vec![0u8; self.block_size as usize];

            self.device.read_block(journal_block, &mut buffer).await?;

            let magic = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
            let block_type = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
            let block_sequence = u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);

            if magic == JOURNAL_MAGIC && block_sequence == sequence {
                match block_type {
                    desc_type if desc_type == JournalBlockType::Descriptor as u32 => {
                        match JournalDescriptorBlock::deserialize(&buffer) {
                            Ok(descriptor) => {
                                total_blocks_in_transaction = descriptor.header.num_blocks;
                                for (i, entry) in descriptor.entries.iter().enumerate() {
                                    blocks_to_replay.push(JournalBlockInfo {
                                        fs_block: entry.block_number,
                                        journal_block: (current_block + i as u32 + 1)
                                            % journal_blocks, // Data blocks follow descriptor
                                        flags: JournalBlockFlags::from_bits_truncate(entry.flags),
                                    });
                                }
                            }
                            Err(_) => return Err(JournalError::Corrupted),
                        }
                    }
                    commit_type if commit_type == JournalBlockType::Commit as u32 => {
                        // Found the commit block, replay all the blocks
                        for block_info in &blocks_to_replay {
                            let mut block_data = vec![0u8; self.block_size as usize];

                            self.device
                                .read_block(
                                    self.map_journal_block(block_info.journal_block),
                                    &mut block_data,
                                )
                                .await?;

                            self.device
                                .write_block(block_info.fs_block as u64, &block_data)
                                .await?;
                        }

                        {
                            let mut superblock = self.superblock.lock();
                            // +3 accounts for descriptor, blocks, and commit block
                            let used_blocks = total_blocks_in_transaction + 3;
                            if sequence == superblock.start_sequence {
                                superblock.first_transaction =
                                    (first_transaction + used_blocks) % journal_blocks;
                                superblock.update_checksum();
                                self.write_superblock_with_lock(&superblock).await?;
                            }
                        }

                        return Ok(());
                    }
                    _ => {}
                }
            }

            current_block = (current_block + 1) % journal_blocks;
        }

        // If we got here, we didn't find a commit block for this transaction
        // That's okay - it means the transaction was aborted
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::sd_card::SD_CARD;
    use alloc::{
        boxed::Box,
        format,
        string::String,
        sync::Arc,
        vec::{self, Vec},
    };
    use spin::RwLock;
    use zerocopy::FromBytes;

    use super::super::{
        block_io::BlockIO,
        cache::{
            block::{BlockCache, CachedBlock},
            Cache,
        },
        journal_structures::{
            JournalBlockFlags, JournalBlockInfo, JournalSuperblock, TransactionState,
        },
        structures::{BlockGroupDescriptor, Superblock, EXT2_SIGNATURE},
    };

    /// Test setup
    struct TestSetup {
        device: Arc<dyn BlockIO>,
        fs_superblock: Arc<RwLock<Superblock>>,
        block_cache: Arc<Mutex<Box<dyn Cache<u32, CachedBlock>>>>,
        allocator: Arc<Mutex<Allocator>>,
        journal: Journal,
        journal_start_block: u32,
        journal_size_blocks: u32,
        reserved_blocks: Vec<u32>,
    }

    impl TestSetup {
        async fn new(journal_size_blocks: u32) -> Self {
            let sd_card = Arc::new(SD_CARD.lock().clone().unwrap());

            let block_size = sd_card.block_size();
            let device_size = sd_card.size_in_bytes();
            let total_blocks = (device_size / block_size) as u32;

            let superblock = Superblock::from_block(sd_card.clone()).await.unwrap();

            if superblock.signature != EXT2_SIGNATURE {
                panic!("Invalid superblock signature");
            }

            let block_groups = superblock.block_group_count();
            let superblock_block_size = superblock.block_size();
            let bgdt_start = if superblock_block_size == 1024 { 2 } else { 1 };

            let fs_superblock = Arc::new(RwLock::new(superblock));

            let device_ref: Arc<dyn BlockIO> = Arc::clone(&sd_card) as Arc<dyn BlockIO>;
            let block_cache = Arc::new(Mutex::new(
                Box::new(BlockCache::new(device_ref, 1024)) as Box<dyn Cache<u32, CachedBlock>>
            ));

            let mut bgdt = Vec::with_capacity(block_groups as usize);
            let block_size_usize: usize = superblock_block_size.try_into().unwrap();
            let block_group_desc_size = core::mem::size_of::<BlockGroupDescriptor>();
            let descriptors_per_block = block_size_usize / block_group_desc_size;
            let blocks_to_read = (block_groups as usize).div_ceil(descriptors_per_block);

            for block in 0..blocks_to_read {
                let mut buff = vec![0u8; block_size_usize];
                match sd_card
                    .read_block((bgdt_start + block as u32) as u64, &mut buff)
                    .await
                {
                    Ok(_) => {}
                    Err(e) => panic!("Device error reading BGDT: {:?}", e),
                }

                for i in 0..descriptors_per_block {
                    let full_idx = block * descriptors_per_block + i;
                    if full_idx < block_groups as usize {
                        bgdt.push(
                            *BlockGroupDescriptor::ref_from_prefix(
                                &buff[i * block_group_desc_size..],
                            )
                            .unwrap()
                            .0,
                        );
                    }
                }
            }

            let bgdt = Arc::new(RwLock::new(bgdt));

            let allocator = Arc::new(Mutex::new(Allocator::new(
                Arc::clone(&fs_superblock),
                Arc::clone(&bgdt),
                Arc::clone(&block_cache),
            )));

            // Choose a safe location for the journal
            let journal_start_block = 10000; // Todo: Calculate based off of blocks

            let device_ref2: Arc<dyn BlockIO> = Arc::clone(&sd_card) as Arc<dyn BlockIO>;
            let journal = Journal::new(
                device_ref2,
                Arc::clone(&fs_superblock),
                Arc::clone(&block_cache),
                journal_start_block,
                journal_size_blocks,
                Arc::clone(&allocator),
            );

            let test_area_start = journal_start_block - 256;
            let mut reserved_blocks = Vec::new();

            for i in 0..10 {
                reserved_blocks.push(test_area_start + i);
            }

            Self {
                device: sd_card,
                fs_superblock,
                block_cache,
                allocator,
                journal,
                journal_start_block,
                journal_size_blocks,
                reserved_blocks,
            }
        }

        /// Initialize the journal and verify it's formatted correctly
        async fn init_journal(&self) -> JournalResult<()> {
            self.journal.format().await?;

            let journal_block = self.journal.map_journal_block(0);
            let mut buffer = vec![0u8; self.journal.block_size as usize];

            self.device
                .read_block(journal_block, &mut buffer)
                .await
                .unwrap();

            let superblock = unsafe {
                let src_ptr = buffer.as_ptr();
                let mut sb = JournalSuperblock::new(0);
                let dst_ptr = &mut sb as *mut JournalSuperblock as *mut u8;
                core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size_of::<JournalSuperblock>());
                sb
            };

            assert!(superblock.is_valid(), "Journal superblock should be valid");

            Ok(())
        }

        /// Get the next available test block
        fn get_test_block(&self, index: usize) -> u32 {
            assert!(
                index < self.reserved_blocks.len(),
                "Test block index out of range"
            );
            self.reserved_blocks[index]
        }

        async fn read_block(&self, block_number: u64) -> Vec<u8> {
            let mut buffer = vec![0u8; self.journal.block_size as usize];
            self.device
                .read_block(block_number, &mut buffer)
                .await
                .unwrap();
            buffer
        }

        async fn write_block(&self, block_number: u64, content: &[u8]) {
            let block_size = self.journal.block_size as usize;
            let mut buffer = vec![0u8; block_size];

            let copy_size = core::cmp::min(content.len(), block_size);
            buffer[..copy_size].copy_from_slice(&content[..copy_size]);

            self.device
                .write_block(block_number, &buffer)
                .await
                .unwrap();
        }

        async fn backup_journal_area(&self) -> Vec<Vec<u8>> {
            let mut backup = Vec::new();
            for i in 0..self.journal_size_blocks {
                let block = self.journal.map_journal_block(i);
                backup.push(self.read_block(block).await);
            }
            backup
        }

        async fn restore_journal_area(&self, backup: &[Vec<u8>]) {
            for (i, block_data) in backup.iter().enumerate() {
                let block = self.journal.map_journal_block(i as u32);
                self.device.write_block(block, block_data).await.unwrap();
            }
        }

        async fn backup_block(&self, block_number: u32) -> Vec<u8> {
            self.read_block(block_number as u64).await
        }

        async fn restore_block(&self, block_number: u32, backup: &[u8]) {
            self.write_block(block_number as u64, backup).await;
        }
    }

    #[test_case]
    async fn test_journal_format() {
        let setup = TestSetup::new(64).await;

        let backup = setup.backup_journal_area().await;

        setup.init_journal().await.unwrap();

        let journal_block = setup.journal.map_journal_block(0);
        let buffer = setup.read_block(journal_block).await;

        let magic = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        assert_eq!(
            magic, JOURNAL_MAGIC,
            "Journal superblock should have correct magic number"
        );

        let block_type = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        assert_eq!(
            block_type,
            JournalBlockType::Superblock as u32,
            "Block type should be superblock"
        );

        setup.restore_journal_area(&backup).await;
    }

    #[test_case]
    async fn test_journal_load() {
        let setup = TestSetup::new(64).await;

        let backup = setup.backup_journal_area().await;

        setup.init_journal().await.unwrap();

        let mut new_journal = Journal::new(
            Arc::clone(&setup.device),
            Arc::clone(&setup.fs_superblock),
            Arc::clone(&setup.block_cache),
            setup.journal_start_block,
            64,
            Arc::clone(&setup.allocator),
        );

        let needs_recovery = new_journal.load().await.unwrap();

        assert!(
            !needs_recovery,
            "Freshly formatted journal shouldn't need recovery"
        );

        assert_eq!(
            new_journal.current_sequence.load(Ordering::SeqCst),
            1,
            "Sequence number should be loaded"
        );
        assert_eq!(
            new_journal.max_transaction_blocks, 1024,
            "Max transaction size should be loaded"
        );

        setup.restore_journal_area(&backup).await;
    }

    #[test_case]
    async fn test_simple_transaction() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;
        let test_block = setup.get_test_block(0);
        let block_backup = setup.backup_block(test_block).await;

        setup.init_journal().await.unwrap();

        let test_content = b"This is test block data that will be journaled";
        setup.write_block(test_block as u64, test_content).await;

        setup.journal.start_transaction().await.unwrap();

        let original_buffer = setup.read_block(test_block as u64).await;
        setup
            .journal
            .journal_block(test_block, &original_buffer)
            .await
            .unwrap();

        let modified_content = b"Modified data that should be overwritten by commit";
        setup.write_block(test_block as u64, modified_content).await;

        setup.journal.commit_transaction().await.unwrap();

        let restored_buffer = setup.read_block(test_block as u64).await;
        assert_eq!(
            &restored_buffer[..test_content.len()],
            test_content,
            "Original data should be restored after commit"
        );

        assert_eq!(
            *setup.journal.transaction_state.lock(),
            TransactionState::None,
            "Transaction state should be None after commit"
        );

        setup.restore_block(test_block, &block_backup).await;
        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_transaction_abort() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;
        let test_block = setup.get_test_block(1);
        let block_backup = setup.backup_block(test_block).await;

        setup.init_journal().await.unwrap();

        let original_data = b"Original block data";
        setup.write_block(test_block as u64, original_data).await;

        setup.journal.start_transaction().await.unwrap();

        let block_buffer = setup.read_block(test_block as u64).await;
        setup
            .journal
            .journal_block(test_block, &block_buffer)
            .await
            .unwrap();

        let modified_data = b"Modified data that should remain after abort";
        setup.write_block(test_block as u64, modified_data).await;

        setup.journal.abort_transaction().await.unwrap();

        let current_buffer = setup.read_block(test_block as u64).await;
        assert_eq!(
            &current_buffer[..modified_data.len()],
            modified_data,
            "Modified data should remain after transaction abort"
        );

        assert!(
            setup.journal.transaction_blocks.lock().is_empty(),
            "Transaction blocks should be cleared after abort"
        );

        setup.restore_block(test_block, &block_backup).await;
        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_multi_block_transaction() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;
        let test_blocks = [
            setup.get_test_block(2),
            setup.get_test_block(3),
            setup.get_test_block(4),
        ];

        let block_backups = [
            setup.backup_block(test_blocks[0]).await,
            setup.backup_block(test_blocks[1]).await,
            setup.backup_block(test_blocks[2]).await,
        ];

        setup.init_journal().await.unwrap();

        setup
            .write_block(test_blocks[0] as u64, b"First block data")
            .await;
        setup
            .write_block(test_blocks[1] as u64, b"Second block data")
            .await;
        setup
            .write_block(test_blocks[2] as u64, b"Third block data")
            .await;

        let original_contents = [
            setup.read_block(test_blocks[0] as u64).await,
            setup.read_block(test_blocks[1] as u64).await,
            setup.read_block(test_blocks[2] as u64).await,
        ];

        setup.journal.start_transaction().await.unwrap();

        for (i, &block_number) in test_blocks.iter().enumerate() {
            setup
                .journal
                .journal_block(block_number, &original_contents[i])
                .await
                .unwrap();
        }

        let modified_data = b"Modified data for all blocks";
        for &block_number in test_blocks.iter() {
            setup.write_block(block_number as u64, modified_data).await;
        }

        assert_eq!(
            setup.journal.transaction_blocks.lock().len(),
            test_blocks.len(),
            "Transaction should have correct number of blocks"
        );

        setup.journal.commit_transaction().await.unwrap();

        for (i, &block_number) in test_blocks.iter().enumerate() {
            let restored_buffer = setup.read_block(block_number as u64).await;
            assert_eq!(
                &restored_buffer[..original_contents[i].len()],
                &original_contents[i][..],
                "Original data should be restored for block {}",
                block_number
            );
        }

        for (i, &block_number) in test_blocks.iter().enumerate() {
            setup.restore_block(block_number, &block_backups[i]).await;
        }
        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_duplicate_block_in_transaction() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;
        let test_block = setup.get_test_block(5);
        let block_backup = setup.backup_block(test_block).await;

        setup.init_journal().await.unwrap();

        let test_data = b"Test block for duplicate test";
        setup.write_block(test_block as u64, test_data).await;

        setup.journal.start_transaction().await.unwrap();

        let block_buffer = setup.read_block(test_block as u64).await;
        setup
            .journal
            .journal_block(test_block, &block_buffer)
            .await
            .unwrap();
        setup
            .journal
            .journal_block(test_block, &block_buffer)
            .await
            .unwrap();

        let blocks = setup.journal.transaction_blocks.lock();
        let count = blocks.iter().filter(|b| b.fs_block == test_block).count();
        assert_eq!(count, 1, "Block should only be added once to transaction");

        drop(blocks);
        setup.journal.abort_transaction().await.unwrap();

        setup.restore_block(test_block, &block_backup).await;
        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_checkpoint() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;
        let test_block = setup.get_test_block(6);
        let block_backup = setup.backup_block(test_block).await;

        setup.init_journal().await.unwrap();

        let test_data = b"Test block for checkpoint test";
        setup.write_block(test_block as u64, test_data).await;

        setup.journal.start_transaction().await.unwrap();
        let block_buffer = setup.read_block(test_block as u64).await;
        setup
            .journal
            .journal_block(test_block, &block_buffer)
            .await
            .unwrap();
        setup.journal.commit_transaction().await.unwrap();

        let sequence_before = {
            let superblock = setup.journal.superblock.lock();
            (superblock.start_sequence, superblock.sequence)
        };

        setup.journal.checkpoint().await.unwrap();

        let sequence_after = {
            let superblock = setup.journal.superblock.lock();
            (superblock.start_sequence, superblock.sequence)
        };

        assert_eq!(
            sequence_after.0, sequence_after.1,
            "start_sequence should equal sequence after checkpoint"
        );
        assert_eq!(
            sequence_before.1, sequence_after.1,
            "sequence should not change during checkpoint"
        );
        assert!(
            sequence_after.0 > sequence_before.0,
            "start_sequence should increase after checkpoint"
        );

        setup.restore_block(test_block, &block_backup).await;
        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_journal_recovery_simulation() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;
        let test_block = setup.get_test_block(7);
        let block_backup = setup.backup_block(test_block).await;

        setup.init_journal().await.unwrap();

        let original_data = b"Original data for recovery test";
        setup.write_block(test_block as u64, original_data).await;

        setup.journal.start_transaction().await.unwrap();

        let block_buffer = setup.read_block(test_block as u64).await;
        setup
            .journal
            .journal_block(test_block, &block_buffer)
            .await
            .unwrap();

        // Commit transaction but don't update the fs blocks directly
        // This simulates writing the journal but crashing before applying changes
        // This is disgusting
        // Can we do better?
        {
            {
                let state = setup.journal.transaction_state.lock();
                if *state != TransactionState::Running {
                    panic!("Transaction should be running");
                }
            }

            let blocks_copy;
            {
                let blocks = setup.journal.transaction_blocks.lock();
                if blocks.is_empty() {
                    panic!("Transaction should have blocks");
                }
                blocks_copy = blocks.clone();
            }

            let sequence = setup.journal.current_sequence.load(Ordering::SeqCst);

            let desc_journal_block = setup.journal.allocate_journal_block(0).unwrap();
            setup
                .journal
                .write_descriptor_block(desc_journal_block, &blocks_copy, sequence)
                .await
                .unwrap();

            let commit_journal_block = setup
                .journal
                .allocate_journal_block(blocks_copy.len() as u32 + 2)
                .unwrap();
            setup
                .journal
                .write_commit_block(commit_journal_block, sequence)
                .await
                .unwrap();

            {
                let mut superblock = setup.journal.superblock.lock();
                superblock.sequence = sequence + 1;
                superblock.update_checksum();
            }

            setup.journal.write_superblock().await.unwrap();
        }

        let changed_data = b"Changed data that should be overwritten by recovery";
        setup.write_block(test_block as u64, changed_data).await;

        let mut new_journal = Journal::new(
            Arc::clone(&setup.device),
            Arc::clone(&setup.fs_superblock),
            Arc::clone(&setup.block_cache),
            setup.journal_start_block,
            64,
            Arc::clone(&setup.allocator),
        );

        let needs_recovery = new_journal.load().await.unwrap();
        assert!(needs_recovery, "Journal should indicate recovery needed");

        new_journal.recover().await.unwrap();

        let restored_buffer = setup.read_block(test_block as u64).await;
        assert_eq!(
            &restored_buffer[..original_data.len()],
            original_data,
            "Original data should be restored after recovery"
        );

        setup.restore_block(test_block, &block_backup).await;
        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_error_conditions() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;

        setup.init_journal().await.unwrap();

        let invalid_block = setup.fs_superblock.read().num_blocks + 1;
        setup.journal.start_transaction().await.unwrap();
        let result = setup.journal.journal_block(invalid_block, &[0; 1024]).await;
        assert!(
            matches!(result, Err(JournalError::InvalidBlock)),
            "Should get InvalidBlock error for block beyond fs size"
        );
        setup.journal.abort_transaction().await.unwrap();

        let result = setup.journal.journal_block(1, &[0; 1024]).await;
        assert!(
            matches!(result, Err(JournalError::NotInTransaction)),
            "Should get NotInTransaction error when not in a transaction"
        );

        setup.journal.start_transaction().await.unwrap();
        let result = setup.journal.start_transaction().await;
        assert!(
            matches!(result, Err(JournalError::AlreadyInTransaction)),
            "Should get AlreadyInTransaction error when starting a second transaction"
        );
        setup.journal.abort_transaction().await.unwrap();

        let result = setup.journal.commit_transaction().await;
        assert!(
            matches!(result, Err(JournalError::NotInTransaction)),
            "Should get NotInTransaction error when committing outside a transaction"
        );

        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_transaction_too_large() {
        let mut setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;
        let test_blocks = [
            setup.get_test_block(8),
            setup.get_test_block(9),
            setup.get_test_block(0),
        ];

        let block_backups = [
            setup.backup_block(test_blocks[0]).await,
            setup.backup_block(test_blocks[1]).await,
            setup.backup_block(test_blocks[2]).await,
        ];

        setup.init_journal().await.unwrap();

        setup.journal.max_transaction_blocks = 2;

        setup.journal.start_transaction().await.unwrap();

        setup
            .write_block(test_blocks[0] as u64, b"Block 1 data")
            .await;
        setup
            .write_block(test_blocks[1] as u64, b"Block 2 data")
            .await;
        setup
            .write_block(test_blocks[2] as u64, b"Block 3 data")
            .await;

        let buffer1 = setup.read_block(test_blocks[0] as u64).await;
        let buffer2 = setup.read_block(test_blocks[1] as u64).await;

        setup
            .journal
            .journal_block(test_blocks[0], &buffer1)
            .await
            .unwrap();
        setup
            .journal
            .journal_block(test_blocks[1], &buffer2)
            .await
            .unwrap();

        // Third block should fail with TransactionTooLarge
        let buffer3 = setup.read_block(test_blocks[2] as u64).await;

        let result = setup.journal.journal_block(test_blocks[2], &buffer3).await;
        assert!(
            matches!(result, Err(JournalError::TransactionTooLarge)),
            "Should get TransactionTooLarge error when exceeding max_transaction_blocks"
        );

        setup.journal.abort_transaction().await.unwrap();

        for (i, &block_number) in test_blocks.iter().enumerate() {
            setup.restore_block(block_number, &block_backups[i]).await;
        }
        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_empty_transaction() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;

        setup.init_journal().await.unwrap();

        setup.journal.start_transaction().await.unwrap();

        setup.journal.commit_transaction().await.unwrap();

        let state = *setup.journal.transaction_state.lock();
        assert_eq!(
            state,
            TransactionState::None,
            "Transaction state should be None after committing empty transaction"
        );

        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_sequence_numbers() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;
        let test_block = setup.get_test_block(0);
        let block_backup = setup.backup_block(test_block).await;

        setup.init_journal().await.unwrap();

        let initial_sequence = setup.journal.current_sequence.load(Ordering::SeqCst);

        let test_data = b"Sequence test data";
        setup.write_block(test_block as u64, test_data).await;

        setup.journal.start_transaction().await.unwrap();
        let buffer = setup.read_block(test_block as u64).await;
        setup
            .journal
            .journal_block(test_block, &buffer)
            .await
            .unwrap();
        setup.journal.commit_transaction().await.unwrap();

        let new_sequence = setup.journal.current_sequence.load(Ordering::SeqCst);
        assert_eq!(
            new_sequence,
            initial_sequence + 1,
            "Sequence number should increment after transaction commit"
        );

        let superblock_sequence = setup.journal.superblock.lock().sequence;
        assert_eq!(
            superblock_sequence, new_sequence,
            "Superblock sequence should match current_sequence"
        );

        setup.restore_block(test_block, &block_backup).await;
        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_journal_descriptor_block_format() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;
        let test_block = setup.get_test_block(1);
        let block_backup = setup.backup_block(test_block).await;

        setup.init_journal().await.unwrap();

        let test_data = b"Test data for descriptor block";
        setup.write_block(test_block as u64, test_data).await;

        setup.journal.start_transaction().await.unwrap();

        let block_buffer = setup.read_block(test_block as u64).await;
        setup
            .journal
            .journal_block(test_block, &block_buffer)
            .await
            .unwrap();

        let blocks = setup.journal.transaction_blocks.lock().clone();
        let sequence = setup.journal.current_sequence.load(Ordering::SeqCst);

        let desc_journal_block = setup.journal.allocate_journal_block(0).unwrap();

        setup
            .journal
            .write_descriptor_block(desc_journal_block, &blocks, sequence)
            .await
            .unwrap();

        let desc_buffer = setup.read_block(desc_journal_block).await;

        let magic = u32::from_le_bytes([
            desc_buffer[0],
            desc_buffer[1],
            desc_buffer[2],
            desc_buffer[3],
        ]);
        assert_eq!(
            magic, JOURNAL_MAGIC,
            "Descriptor block should have correct magic number"
        );

        let block_type = u32::from_le_bytes([
            desc_buffer[4],
            desc_buffer[5],
            desc_buffer[6],
            desc_buffer[7],
        ]);
        assert_eq!(
            block_type,
            JournalBlockType::Descriptor as u32,
            "Block type should be descriptor"
        );

        let descriptor = JournalDescriptorBlock::deserialize(&desc_buffer).unwrap();

        let desc_sequence = descriptor.header.sequence;
        let desc_num_blocks = descriptor.header.num_blocks;

        assert_eq!(
            desc_sequence, sequence,
            "Descriptor block should have correct sequence number"
        );
        assert_eq!(
            desc_num_blocks, 1,
            "Descriptor block should have correct block count"
        );

        assert_eq!(descriptor.entries.len(), 1, "Should have one entry");

        let entry_block_number = descriptor.entries[0].block_number;
        assert_eq!(
            entry_block_number, test_block,
            "Entry should have correct block number"
        );

        setup.journal.abort_transaction().await.unwrap();

        setup.restore_block(test_block, &block_backup).await;
        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_journal_commit_block_format() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;

        setup.init_journal().await.unwrap();

        let sequence = 42;
        let commit_journal_block = setup.journal.allocate_journal_block(0).unwrap();
        setup
            .journal
            .write_commit_block(commit_journal_block, sequence)
            .await
            .unwrap();

        let commit_buffer = setup.read_block(commit_journal_block).await;

        let magic = u32::from_le_bytes([
            commit_buffer[0],
            commit_buffer[1],
            commit_buffer[2],
            commit_buffer[3],
        ]);
        assert_eq!(
            magic, JOURNAL_MAGIC,
            "Commit block should have correct magic number"
        );

        let block_type = u32::from_le_bytes([
            commit_buffer[4],
            commit_buffer[5],
            commit_buffer[6],
            commit_buffer[7],
        ]);
        assert_eq!(
            block_type,
            JournalBlockType::Commit as u32,
            "Block type should be commit"
        );

        let block_sequence = u32::from_le_bytes([
            commit_buffer[8],
            commit_buffer[9],
            commit_buffer[10],
            commit_buffer[11],
        ]);
        assert_eq!(block_sequence, sequence, "Sequence number should match");

        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_journal_superblock_checksum() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;

        setup.init_journal().await.unwrap();

        {
            let journal_block = setup.journal.map_journal_block(0);
            let mut buffer = setup.read_block(journal_block).await;

            let mut superblock = unsafe {
                let src_ptr = buffer.as_ptr();
                let mut sb = JournalSuperblock::new(0);
                let dst_ptr = &mut sb as *mut JournalSuperblock as *mut u8;
                core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size_of::<JournalSuperblock>());
                sb
            };

            superblock.checksum += 1;

            unsafe {
                let src_ptr = &superblock as *const JournalSuperblock as *const u8;
                let dst_ptr = buffer.as_mut_ptr();
                core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size_of::<JournalSuperblock>());
            }

            setup
                .device
                .write_block(journal_block, &buffer)
                .await
                .unwrap();
        }

        let mut new_journal = Journal::new(
            Arc::clone(&setup.device),
            Arc::clone(&setup.fs_superblock),
            Arc::clone(&setup.block_cache),
            setup.journal_start_block,
            64,
            Arc::clone(&setup.allocator),
        );

        let result = new_journal.load().await;
        assert!(
            matches!(result, Err(JournalError::ChecksumMismatch)),
            "Loading journal with corrupted checksum should fail"
        );

        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_multiple_transactions() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;
        let test_blocks = [setup.get_test_block(2), setup.get_test_block(3)];

        let block_backups = [
            setup.backup_block(test_blocks[0]).await,
            setup.backup_block(test_blocks[1]).await,
        ];

        setup.init_journal().await.unwrap();

        let initial_data = [
            b"Initial data for block 0".as_slice(),
            b"Initial data for block 1".as_slice(),
        ];

        setup
            .write_block(test_blocks[0] as u64, initial_data[0])
            .await;
        setup
            .write_block(test_blocks[1] as u64, initial_data[1])
            .await;

        setup.journal.start_transaction().await.unwrap();

        let buffer0 = setup.read_block(test_blocks[0] as u64).await;
        setup
            .journal
            .journal_block(test_blocks[0], &buffer0)
            .await
            .unwrap();

        let modified_data_1 = b"Modified data for first transaction";
        setup
            .write_block(test_blocks[0] as u64, modified_data_1)
            .await;

        setup.journal.commit_transaction().await.unwrap();
        setup.journal.checkpoint().await.unwrap();

        let restored_buffer0 = setup.read_block(test_blocks[0] as u64).await;
        assert_eq!(
            &restored_buffer0[..initial_data[0].len()],
            initial_data[0],
            "Block 0 should be restored after first transaction"
        );

        setup.journal.start_transaction().await.unwrap();

        let buffer1 = setup.read_block(test_blocks[1] as u64).await;
        setup
            .journal
            .journal_block(test_blocks[1], &buffer1)
            .await
            .unwrap();

        let modified_data_2 = b"Modified data for second transaction";
        setup
            .write_block(test_blocks[1] as u64, modified_data_2)
            .await;

        setup.journal.commit_transaction().await.unwrap();

        let restored_buffer1 = setup.read_block(test_blocks[1] as u64).await;
        assert_eq!(
            &restored_buffer1[..initial_data[1].len()],
            initial_data[1],
            "Block 1 should be restored after second transaction"
        );

        let final_sequence = setup.journal.current_sequence.load(Ordering::SeqCst);
        assert_eq!(
            final_sequence, 3,
            "Sequence number should be 3 after two transactions"
        );

        setup.restore_block(test_blocks[0], &block_backups[0]).await;
        setup.restore_block(test_blocks[1], &block_backups[1]).await;
        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_large_transaction() {
        let setup = TestSetup::new(128).await;

        let journal_backup = setup.backup_journal_area().await;

        setup.init_journal().await.unwrap();

        let mut test_blocks = Vec::new();
        let mut block_backups = Vec::new();
        let mut original_data = Vec::new();

        for i in 0..10 {
            let block = setup.get_test_block(i);
            test_blocks.push(block);

            block_backups.push(setup.backup_block(block).await);

            let data = format!("Original data for block {}", i).into_bytes();
            setup.write_block(block as u64, &data).await;

            original_data.push(setup.read_block(block as u64).await);
        }

        setup.journal.start_transaction().await.unwrap();

        for (i, &block) in test_blocks.iter().enumerate() {
            setup
                .journal
                .journal_block(block, &original_data[i])
                .await
                .unwrap();
        }

        let modified_data = b"This data should be overwritten after commit";
        for &block in &test_blocks {
            setup.write_block(block as u64, modified_data).await;
        }

        setup.journal.commit_transaction().await.unwrap();

        for (i, &block) in test_blocks.iter().enumerate() {
            let restored = setup.read_block(block as u64).await;
            assert_eq!(
                restored, original_data[i],
                "Block {} should be restored to original data",
                block
            );
        }

        for (i, &block) in test_blocks.iter().enumerate() {
            setup.restore_block(block, &block_backups[i]).await;
        }

        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_journal_stress_test() {
        let setup = TestSetup::new(256).await;

        let journal_backup = setup.backup_journal_area().await;

        setup.init_journal().await.unwrap();

        let test_blocks = (0..10).map(|i| setup.get_test_block(i)).collect::<Vec<_>>();

        let mut block_backups = Vec::new();
        for &block in &test_blocks {
            block_backups.push((block, setup.backup_block(block).await));
        }

        const NUM_CYCLES: usize = 10;

        for (i, &block) in test_blocks.iter().enumerate() {
            let data = format!("Initial data for block {}", i).into_bytes();
            setup.write_block(block as u64, &data).await;
        }

        for cycle in 0..NUM_CYCLES {
            setup.journal.start_transaction().await.unwrap();

            // Journal a subset of blocks (alternate blocks each cycle)
            let blocks_to_journal = test_blocks
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 2 == cycle % 2)
                .map(|(_, b)| *b)
                .collect::<Vec<_>>();

            for &block in &blocks_to_journal {
                let buffer = setup.read_block(block as u64).await;
                setup.journal.journal_block(block, &buffer).await.unwrap();
            }

            for &block in &blocks_to_journal {
                let data = format!("Modified in cycle {} for block {}", cycle, block).into_bytes();
                setup.write_block(block as u64, &data).await;
            }

            if cycle % 2 == 0 {
                setup.journal.commit_transaction().await.unwrap();

                for &block in &blocks_to_journal {
                    let restored = setup.read_block(block as u64).await;
                    let expected_string = String::from("Initial data for block");
                    let expected_start = expected_string.as_bytes();
                    assert!(
                        restored.starts_with(expected_start),
                        "Block {} should be restored after commit in cycle {}",
                        block,
                        cycle
                    );
                }
            } else {
                setup.journal.abort_transaction().await.unwrap();

                for &block in &blocks_to_journal {
                    let current = setup.read_block(block as u64).await;
                    let expected_string = format!("Modified in cycle {}", cycle);
                    let expected_start = expected_string.as_bytes();
                    assert!(
                        current.starts_with(expected_start),
                        "Block {} should remain modified after abort in cycle {}",
                        block,
                        cycle
                    );

                    // Manually reset blocks for next cycle
                    let data = format!(
                        "Initial data for block {}",
                        test_blocks.iter().position(|&b| b == block).unwrap()
                    )
                    .into_bytes();
                    setup.write_block(block as u64, &data).await;
                }
            }

            // Checkpoint every few cycles
            if cycle % 3 == 2 {
                setup.journal.checkpoint().await.unwrap();
            }
        }

        for (block, backup) in block_backups {
            setup.restore_block(block, &backup).await;
        }
        setup.restore_journal_area(&journal_backup).await;
    }

    #[test_case]
    async fn test_journal_block_overwrite() {
        let setup = TestSetup::new(64).await;

        let journal_backup = setup.backup_journal_area().await;
        let test_block = setup.get_test_block(0);
        let block_backup = setup.backup_block(test_block).await;

        setup.init_journal().await.unwrap();

        let original_data = b"Original data for block overwrite test";
        setup.write_block(test_block as u64, original_data).await;

        // First transaction
        setup.journal.start_transaction().await.unwrap();
        let buffer = setup.read_block(test_block as u64).await;
        setup
            .journal
            .journal_block(test_block, &buffer)
            .await
            .unwrap();

        let first_modified = b"First modified data";
        setup.write_block(test_block as u64, first_modified).await;

        setup.journal.commit_transaction().await.unwrap();

        let restored = setup.read_block(test_block as u64).await;
        assert_eq!(
            &restored[..original_data.len()],
            original_data,
            "Block should be restored to original data after first transaction"
        );

        // Start second transaction with the same block
        setup.journal.start_transaction().await.unwrap();
        let buffer = setup.read_block(test_block as u64).await;
        setup
            .journal
            .journal_block(test_block, &buffer)
            .await
            .unwrap();

        // Modify the block again
        let second_modified = b"Second modified data";
        setup.write_block(test_block as u64, second_modified).await;

        setup.journal.commit_transaction().await.unwrap();

        let restored = setup.read_block(test_block as u64).await;
        assert_eq!(
            &restored[..original_data.len()],
            original_data,
            "Block should be restored to original data after second transaction"
        );

        setup.restore_block(test_block, &block_backup).await;
        setup.restore_journal_area(&journal_backup).await;
    }
}
