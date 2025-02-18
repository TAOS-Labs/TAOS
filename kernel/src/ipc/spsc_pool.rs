use super::spsc::{Receiver, Sender, SpscChannel, SPSC_DEFAULT_CAPACITY};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

#[derive(Debug)]
pub enum PoolError {
    NoChannelsAvailable,
    InvalidChannelId,
    ChannelInUse,
    AllocationFailed,
    SenderAlreadyReturned,
    ReceiverAlreadyReturned,
    ChannelPartMissing,
}

#[derive(Default)]
struct ChannelState<T> {
    sender: Option<Sender<T>>,
    receiver: Option<Receiver<T>>,
}

// Need this because can't assume `T` implements default
impl<T> ChannelState<T> {
    fn new() -> Self {
        Self {
            sender: None,
            receiver: None,
        }
    }
}

pub struct ChannelPool<T> {
    channels: Vec<Option<ChannelState<T>>>,
    available: Vec<AtomicUsize>,
    allocation_lock: Mutex<()>,
}

impl<T> ChannelPool<T> {
    pub fn new(num_channels: usize) -> Self {
        assert!(num_channels > 0, "Pool must have at least one channel");

        // Initialize channels with sender/receiver pairs
        let channels = (0..num_channels)
            .map(|_| {
                let (sender, receiver) = SpscChannel::new(SPSC_DEFAULT_CAPACITY).split();
                Some(ChannelState {
                    sender: Some(sender),
                    receiver: Some(receiver),
                })
            })
            .collect();

        let bitmap_words = (num_channels + 63) / 64;
        let mut available = Vec::with_capacity(bitmap_words);

        for word_idx in 0..bitmap_words {
            let remaining_channels = num_channels.saturating_sub(word_idx * 64);
            let valid_bits = if remaining_channels >= 64 {
                !0
            } else {
                (1 << remaining_channels) - 1
            };
            available.push(AtomicUsize::new(valid_bits));
        }

        Self {
            channels,
            available,
            allocation_lock: Mutex::new(()),
        }
    }

    fn find_first_set(word: usize, max_valid_bits: usize) -> Option<usize> {
        if word == 0 {
            return None;
        }
        let idx = word.trailing_zeros() as usize;
        if idx < max_valid_bits {
            Some(idx)
        } else {
            None
        }
    }

    fn try_claim_bit(word: &AtomicUsize, bit_idx: usize) -> bool {
        let bit_mask = 1 << bit_idx;
        let mut current = word.load(Ordering::Acquire);

        loop {
            if current & bit_mask == 0 {
                return false; // Bit already claimed
            }

            match word.compare_exchange_weak(
                current,
                current & !bit_mask,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(new) => current = new,
            }
        }
    }

    fn find_free_pair(&self) -> Option<(usize, usize)> {
        let channels_per_word = 64;

        for (word_idx, word) in self.available.iter().enumerate() {
            let value = word.load(Ordering::Acquire);
            if value == 0 {
                continue;
            }

            let remaining_channels = self
                .channels
                .len()
                .saturating_sub(word_idx * channels_per_word);
            let valid_bits = core::cmp::min(remaining_channels, channels_per_word);

            // Try to find pair in same word
            if let Some(bit_idx1) = Self::find_first_set(value, valid_bits) {
                let remaining = value & !(1 << bit_idx1);
                if let Some(bit_idx2) = Self::find_first_set(remaining, valid_bits) {
                    let idx1 = word_idx * channels_per_word + bit_idx1;
                    let idx2 = word_idx * channels_per_word + bit_idx2;

                    if idx1 < self.channels.len() && idx2 < self.channels.len() {
                        return Some((idx1, idx2));
                    }
                }
            }

            // Try to find pair across words
            if let Some(bit_idx1) = Self::find_first_set(value, valid_bits) {
                let idx1 = word_idx * channels_per_word + bit_idx1;

                for second_word_idx in word_idx + 1..self.available.len() {
                    let second_word = self.available[second_word_idx].load(Ordering::Acquire);
                    if second_word == 0 {
                        continue;
                    }

                    let remaining_channels = self
                        .channels
                        .len()
                        .saturating_sub(second_word_idx * channels_per_word);
                    let valid_bits = core::cmp::min(remaining_channels, channels_per_word);

                    if let Some(bit_idx2) = Self::find_first_set(second_word, valid_bits) {
                        let idx2 = second_word_idx * channels_per_word + bit_idx2;

                        if idx2 < self.channels.len() {
                            return Some((idx1, idx2));
                        }
                    }
                }
            }
        }
        None
    }

    fn find_and_claim_pair(&self) -> Option<(usize, usize)> {
        let _guard = self.allocation_lock.lock();

        let result = self.find_free_pair();
        if let Some((idx1, idx2)) = result {
            self.mark_channel_used(idx1);
            self.mark_channel_used(idx2);
        }
        result
    }

    fn mark_channel_used(&self, channel_idx: usize) {
        let word_idx = channel_idx / 64;
        let bit_idx = channel_idx % 64;
        self.available[word_idx].fetch_and(!(1 << bit_idx), Ordering::Release);
    }

    fn mark_channel_available(&self, channel_idx: usize) {
        let word_idx = channel_idx / 64;
        let bit_idx = channel_idx % 64;
        self.available[word_idx].fetch_or(1 << bit_idx, Ordering::Release);
    }

    pub fn allocate_pair(
        &mut self,
    ) -> Result<((Sender<T>, Receiver<T>), (Sender<T>, Receiver<T>)), PoolError> {
        let (idx1, idx2) = self
            .find_and_claim_pair()
            .ok_or(PoolError::NoChannelsAvailable)?;

        let mut state1 = self.channels[idx1]
            .take()
            .ok_or(PoolError::AllocationFailed)?;

        let mut state2 = match self.channels[idx2].take() {
            Some(state2) => state2,
            None => {
                // Rollback first channel if second fails
                self.channels[idx1] = Some(state1);
                self.mark_channel_available(idx1);
                return Err(PoolError::AllocationFailed);
            }
        };

        // Both parts must be present in both channels
        match (
            state1.sender.take(),
            state1.receiver.take(),
            state2.sender.take(),
            state2.receiver.take(),
        ) {
            (Some(s1), Some(r1), Some(s2), Some(r2)) => Ok(((s1, r1), (s2, r2))),
            _ => {
                self.channels[idx1] = Some(state1);
                self.channels[idx2] = Some(state2);
                self.mark_channel_available(idx1);
                self.mark_channel_available(idx2);
                Err(PoolError::ChannelPartMissing)
            }
        }
    }

    pub fn get_channel(
        &mut self,
        channel_idx: usize,
    ) -> Result<(Sender<T>, Receiver<T>), PoolError> {
        if channel_idx >= self.channels.len() {
            return Err(PoolError::InvalidChannelId);
        }

        let _guard = self.allocation_lock.lock();
        let word_idx = channel_idx / 64;
        let bit_idx = channel_idx % 64;

        if !Self::try_claim_bit(&self.available[word_idx], bit_idx) {
            return Err(PoolError::ChannelInUse);
        }

        let mut state = self.channels[channel_idx].take().ok_or_else(|| {
            self.mark_channel_available(channel_idx);
            PoolError::ChannelInUse
        })?;

        // Both parts must be present to get a channel
        match (state.sender.take(), state.receiver.take()) {
            (Some(sender), Some(receiver)) => Ok((sender, receiver)),
            _ => {
                self.channels[channel_idx] = Some(state);
                self.mark_channel_available(channel_idx);
                Err(PoolError::ChannelPartMissing)
            }
        }
    }

    pub fn return_sender(
        &mut self,
        channel_idx: usize,
        sender: Sender<T>,
    ) -> Result<(), PoolError> {
        if channel_idx >= self.channels.len() {
            return Err(PoolError::InvalidChannelId);
        }

        let _guard = self.allocation_lock.lock();

        let state = self.channels[channel_idx].get_or_insert_with(ChannelState::new);
        if state.sender.is_some() {
            return Err(PoolError::SenderAlreadyReturned);
        }

        state.sender = Some(sender);

        // Mark channel as available only if both parts are present
        if state.receiver.is_some() {
            self.mark_channel_available(channel_idx);
        }

        Ok(())
    }

    pub fn return_receiver(
        &mut self,
        channel_idx: usize,
        receiver: Receiver<T>,
    ) -> Result<(), PoolError> {
        if channel_idx >= self.channels.len() {
            return Err(PoolError::InvalidChannelId);
        }

        let _guard = self.allocation_lock.lock();

        let state = self.channels[channel_idx].get_or_insert_with(ChannelState::new);
        if state.receiver.is_some() {
            return Err(PoolError::ReceiverAlreadyReturned);
        }

        state.receiver = Some(receiver);

        // Mark channel as available only if both parts are present
        if state.sender.is_some() {
            self.mark_channel_available(channel_idx);
        }

        Ok(())
    }

    pub fn capacity(&self) -> usize {
        self.channels.len()
    }

    pub fn available_channels(&self) -> usize {
        self.available
            .iter()
            .enumerate()
            .map(|(word_idx, word)| {
                let value = word.load(Ordering::Relaxed);
                let remaining_channels = self.channels.len().saturating_sub(word_idx * 64);
                let valid_bits = core::cmp::min(remaining_channels, 64);
                (value & ((1 << valid_bits) - 1)).count_ones() as usize
            })
            .sum()
    }
}

impl<T> Drop for ChannelPool<T> {
    fn drop(&mut self) {
        // Channels will be dropped automatically through Vec's Drop implementation
    }
}
