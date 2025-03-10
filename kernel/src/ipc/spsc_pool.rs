use super::spsc::{Receiver, Sender, SpscChannel, SPSC_DEFAULT_CAPACITY};
use alloc::{sync::Arc, vec::Vec};
use spin::Mutex;

#[derive(Debug)]
pub enum PoolError {
    NoChannelsAvailable,
    InvalidChannelId,
    ChannelInUse,
    AllocationFailed,
    SenderAlreadyReturned,
    ReceiverAlreadyReturned,
}

#[derive(Default)]
struct ChannelState {
    sender_out: bool,
    receiver_out: bool,
}

struct ChannelEntry<T> {
    channel: Arc<SpscChannel<T>>,
    state: ChannelState,
}

struct PoolData<T> {
    channels: Vec<Option<ChannelEntry<T>>>,
    available: Vec<usize>,
}

pub struct ChannelPool<T> {
    allocation_lock: Mutex<PoolData<T>>,
}

impl<T> ChannelPool<T> {
    pub fn new(num_channels: usize) -> Self {
        assert!(num_channels > 0, "Pool must have at least one channel");

        let channels = (0..num_channels)
            .map(|_| {
                Some(ChannelEntry {
                    channel: Arc::new(SpscChannel::new(SPSC_DEFAULT_CAPACITY)),
                    state: ChannelState::default(),
                })
            })
            .collect();

        let bitmap_words = num_channels.div_ceil(64);
        let mut available = Vec::with_capacity(bitmap_words);
        for word_idx in 0..bitmap_words {
            let remaining_channels = num_channels.saturating_sub(word_idx * 64);
            let valid_bits = if remaining_channels >= 64 {
                !0
            } else {
                (1 << remaining_channels) - 1
            };
            available.push(valid_bits);
        }

        Self {
            allocation_lock: Mutex::new(PoolData {
                channels,
                available,
            }),
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

    fn find_free_pair(data: &PoolData<T>) -> Option<(usize, usize)> {
        let channels_per_word = 64;

        for (word_idx, &word) in data.available.iter().enumerate() {
            if word == 0 {
                continue;
            }

            let remaining_channels = data
                .channels
                .len()
                .saturating_sub(word_idx * channels_per_word);
            let valid_bits = core::cmp::min(remaining_channels, channels_per_word);

            // Try to find pair in same word
            if let Some(bit_idx1) = Self::find_first_set(word, valid_bits) {
                let remaining = word & !(1 << bit_idx1);
                if let Some(bit_idx2) = Self::find_first_set(remaining, valid_bits) {
                    let idx1 = word_idx * channels_per_word + bit_idx1;
                    let idx2 = word_idx * channels_per_word + bit_idx2;

                    if idx1 < data.channels.len() && idx2 < data.channels.len() {
                        return Some((idx1, idx2));
                    }
                }
            }

            // Try next word if needed
            if let Some(bit_idx1) = Self::find_first_set(word, valid_bits) {
                let idx1 = word_idx * channels_per_word + bit_idx1;

                for second_word_idx in word_idx + 1..data.available.len() {
                    let second_word = data.available[second_word_idx];
                    if second_word == 0 {
                        continue;
                    }

                    let remaining_channels = data
                        .channels
                        .len()
                        .saturating_sub(second_word_idx * channels_per_word);
                    let valid_bits = core::cmp::min(remaining_channels, channels_per_word);

                    if let Some(bit_idx2) = Self::find_first_set(second_word, valid_bits) {
                        let idx2 = second_word_idx * channels_per_word + bit_idx2;

                        if idx2 < data.channels.len() {
                            return Some((idx1, idx2));
                        }
                    }
                }
            }
        }
        None
    }

    fn mark_channel_used(data: &mut PoolData<T>, channel_idx: usize) {
        let word_idx = channel_idx / 64;
        let bit_idx = channel_idx % 64;
        data.available[word_idx] &= !(1 << bit_idx);
    }

    fn mark_channel_available(data: &mut PoolData<T>, channel_idx: usize) {
        let word_idx = channel_idx / 64;
        let bit_idx = channel_idx % 64;
        data.available[word_idx] |= 1 << bit_idx;
    }

    #[allow(clippy::type_complexity)]
    pub fn allocate_pair(
        &self,
    ) -> Result<((Sender<T>, Receiver<T>), (Sender<T>, Receiver<T>)), PoolError> {
        let mut data = self.allocation_lock.lock();

        let (idx1, idx2) = Self::find_free_pair(&data).ok_or(PoolError::NoChannelsAvailable)?;

        // Get entries
        if data.channels[idx1].is_none() || data.channels[idx2].is_none() {
            return Err(PoolError::ChannelInUse);
        }

        // Get channel references and create pairs
        let (channel1, channel2) = {
            let entry1 = data.channels[idx1].as_ref().unwrap();
            let entry2 = data.channels[idx2].as_ref().unwrap();

            if entry1.channel.is_fully_dropped() {
                entry1.channel.reset();
            }
            if entry2.channel.is_fully_dropped() {
                entry2.channel.reset();
            }

            (entry1.channel.clone(), entry2.channel.clone())
        };

        // Update states
        if let Some(entry) = data.channels[idx1].as_mut() {
            entry.state.sender_out = true;
            entry.state.receiver_out = true;
        }
        if let Some(entry) = data.channels[idx2].as_mut() {
            entry.state.sender_out = true;
            entry.state.receiver_out = true;
        }

        // Mark both as used
        Self::mark_channel_used(&mut data, idx1);
        Self::mark_channel_used(&mut data, idx2);

        Ok((
            (
                Sender {
                    channel: channel1.clone(),
                },
                Receiver { channel: channel1 },
            ),
            (
                Sender {
                    channel: channel2.clone(),
                },
                Receiver { channel: channel2 },
            ),
        ))
    }

    pub fn return_sender(&self, channel_idx: usize, sender: Sender<T>) -> Result<(), PoolError> {
        let mut data = self.allocation_lock.lock();

        if channel_idx >= data.channels.len() {
            return Err(PoolError::InvalidChannelId);
        }

        let entry = data.channels[channel_idx]
            .as_mut()
            .ok_or(PoolError::ChannelInUse)?;

        if !entry.state.sender_out {
            return Err(PoolError::SenderAlreadyReturned);
        }

        entry.state.sender_out = false;

        // Drop sender
        drop(sender);

        // If both parts are back, clean up and mark available
        if !entry.state.receiver_out {
            if entry.channel.is_fully_dropped() {
                unsafe {
                    entry.channel.cleanup();
                }
            }
            Self::mark_channel_available(&mut data, channel_idx);
        }

        Ok(())
    }

    pub fn return_receiver(
        &self,
        channel_idx: usize,
        receiver: Receiver<T>,
    ) -> Result<(), PoolError> {
        let mut data = self.allocation_lock.lock();

        if channel_idx >= data.channels.len() {
            return Err(PoolError::InvalidChannelId);
        }

        let entry = data.channels[channel_idx]
            .as_mut()
            .ok_or(PoolError::ChannelInUse)?;

        if !entry.state.receiver_out {
            return Err(PoolError::ReceiverAlreadyReturned);
        }

        entry.state.receiver_out = false;

        // Drop receiver
        drop(receiver);

        // If both parts are back, clean up and mark available
        if !entry.state.sender_out {
            if entry.channel.is_fully_dropped() {
                unsafe {
                    entry.channel.cleanup();
                }
            }
            Self::mark_channel_available(&mut data, channel_idx);
        }

        Ok(())
    }

    pub fn capacity(&self) -> usize {
        let data = self.allocation_lock.lock();
        data.channels.len()
    }

    pub fn available_channels(&self) -> usize {
        let data = self.allocation_lock.lock();
        data.available
            .iter()
            .enumerate()
            .map(|(word_idx, &word)| {
                let remaining_channels = data.channels.len().saturating_sub(word_idx * 64);
                let valid_bits = core::cmp::min(remaining_channels, 64);
                (word & ((1 << valid_bits) - 1)).count_ones() as usize
            })
            .sum()
    }
}

impl<T> Drop for ChannelPool<T> {
    fn drop(&mut self) {
        let mut data = self.allocation_lock.lock();
        for entry in data.channels.iter_mut().flatten() {
            unsafe {
                entry.channel.cleanup();
            }
        }
    }
}
