use alloc::{boxed::Box, sync::Arc, vec::Vec};
use alloc::{sync::Arc, collections::BTreeMap};use alloc::{sync::Arc, collections::BTreeMap};
use std::sync::Mutex;
use core::{
    cell::UnsafeCell,
    future::Future,
    mem::MaybeUninit,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};

pub const SPSC_DEFAULT_CAPACITY: usize = 6;

pub struct SpscChannel<T> {
    buffer: Box<[UnsafeCell<MaybeUninit<T>>]>,
    capacity: usize,
    head: AtomicUsize,
    tail: AtomicUsize,
    rx_waker: UnsafeCell<Option<Waker>>,
    tx_waker: UnsafeCell<Option<Waker>>,
    is_dropped: AtomicUsize,
}

const NOT_DROPPED: usize = 0;
const SENDER_DROPPED: usize = 1;
const RECEIVER_DROPPED: usize = 2;

unsafe impl<T: Send> Send for SpscChannel<T> {}
unsafe impl<T: Send> Sync for SpscChannel<T> {}

pub struct ChannelMapping<T> {
    pid_to_channel: Arc<Mutex<BTreeMap<u32, SpscChannel<T>>>>, 
}

impl<T>  ChannelMapping<T> {
    pub fn new() -> Self {
        Self {
            pid_to_channel: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn add_chhannel(&self, pid: u32, channel: SpscChannel<T>) {

    }

    pub fn get_chhannel(&self, pid: u32, channel: SpscChannel<T>) {

    }

    pub fn remove_channel(&self, pid: u32) {
        
    }

    //register twice
}

pub struct Sender<T> {
    pub channel: Arc<SpscChannel<T>>,
}

pub struct Receiver<T> {
    pub channel: Arc<SpscChannel<T>>,
}

unsafe impl<T: Send> Send for Sender<T> {}
unsafe impl<T: Send> Send for Receiver<T> {}

#[derive(Debug)]
pub enum SendError<T> {
    Full(T),
    Disconnected(T),
}

#[derive(Debug)]
pub enum RecvError {
    Empty,
    Disconnected,
}

impl<T> Default for SpscChannel<T> {
    fn default() -> Self {
        Self::new(SPSC_DEFAULT_CAPACITY)
    }
}

impl<T> SpscChannel<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "capacity must be greater than 0");
        let buffer = (0..capacity)
            .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self {
            buffer,
            capacity,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            rx_waker: UnsafeCell::new(None),
            tx_waker: UnsafeCell::new(None),
            is_dropped: AtomicUsize::new(NOT_DROPPED),
        }
    }

    pub fn split(self) -> (Sender<T>, Receiver<T>) {
        let channel = Arc::new(self);
        (
            Sender {
                channel: channel.clone(),
            },
            Receiver { channel },
        )
    }

    ///
    /// # Safety
    /// TODO
    pub unsafe fn cleanup(&self) {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        if head <= tail {
            for i in head..tail {
                let idx = i % self.capacity;
                (*self.buffer[idx].get()).assume_init_drop();
            }
        } else {
            for i in head..self.capacity {
                (*self.buffer[i].get()).assume_init_drop();
            }
            for i in 0..tail {
                (*self.buffer[i].get()).assume_init_drop();
            }
        }
    }

    pub fn is_fully_dropped(&self) -> bool {
        let state = self.is_dropped.load(Ordering::Acquire);
        state == (SENDER_DROPPED | RECEIVER_DROPPED)
    }

    pub fn reset(&self) {
        self.head.store(0, Ordering::Release);
        self.tail.store(0, Ordering::Release);
        self.is_dropped.store(NOT_DROPPED, Ordering::Release);
        unsafe {
            *self.rx_waker.get() = None;
            *self.tx_waker.get() = None;
        }
    }
}

impl<T> Sender<T> {
    pub fn try_send(&self, value: T) -> Result<(), SendError<T>> {
        let channel = &*self.channel;

        if channel.is_dropped.load(Ordering::Acquire) & RECEIVER_DROPPED != 0 {
            return Err(SendError::Disconnected(value));
        }

        let tail = channel.tail.load(Ordering::Acquire);
        let head = channel.head.load(Ordering::Acquire);

        if tail.wrapping_sub(head) < channel.capacity {
            unsafe {
                (*channel.buffer[tail % channel.capacity].get()).write(value);
            }
            channel.tail.store(tail.wrapping_add(1), Ordering::Release);

            if let Some(waker) = unsafe { (*channel.rx_waker.get()).take() } {
                waker.wake();
            }
            Ok(())
        } else {
            Err(SendError::Full(value))
        }
    }

    pub fn send(&self, value: T) -> SendFuture<T> {
        SendFuture {
            sender: self,
            value: Some(value),
        }
    }
}

impl<T> Receiver<T> {
    pub fn try_recv(&self) -> Result<T, RecvError> {
        let channel = &*self.channel;
        let head = channel.head.load(Ordering::Acquire);
        let tail = channel.tail.load(Ordering::Acquire);

        if head != tail {
            let value =
                unsafe { (*channel.buffer[head % channel.capacity].get()).assume_init_read() };
            channel.head.store(head.wrapping_add(1), Ordering::Release);

            if let Some(waker) = unsafe { (*channel.tx_waker.get()).take() } {
                waker.wake();
            }
            Ok(value)
        } else if channel.is_dropped.load(Ordering::Acquire) & SENDER_DROPPED != 0 {
            Err(RecvError::Disconnected)
        } else {
            Err(RecvError::Empty)
        }
    }

    pub fn recv(&self) -> RecvFuture<T> {
        RecvFuture { receiver: self }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let channel = &*self.channel;
        channel
            .is_dropped
            .fetch_or(SENDER_DROPPED, Ordering::AcqRel);

        if let Some(waker) = unsafe { (*channel.rx_waker.get()).take() } {
            waker.wake();
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let channel = &*self.channel;
        channel
            .is_dropped
            .fetch_or(RECEIVER_DROPPED, Ordering::AcqRel);

        if let Some(waker) = unsafe { (*channel.tx_waker.get()).take() } {
            waker.wake();
        }
    }
}

pub struct SendFuture<'a, T> {
    sender: &'a Sender<T>,
    value: Option<T>,
}

impl<T> Future for SendFuture<'_, T> {
    type Output = Result<(), SendError<T>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        let value = this.value.take().expect("polled after completion");

        match this.sender.try_send(value) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(SendError::Full(value)) => {
                this.value = Some(value);
                unsafe {
                    *this.sender.channel.tx_waker.get() = Some(cx.waker().clone());
                }
                Poll::Pending
            }
            Err(SendError::Disconnected(value)) => Poll::Ready(Err(SendError::Disconnected(value))),
        }
    }
}

pub struct RecvFuture<'a, T> {
    receiver: &'a Receiver<T>,
}

impl<T> Future for RecvFuture<'_, T> {
    type Output = Result<T, RecvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.receiver.try_recv() {
            Ok(value) => Poll::Ready(Ok(value)),
            Err(RecvError::Empty) => {
                unsafe {
                    *self.receiver.channel.rx_waker.get() = Some(cx.waker().clone());
                }
                Poll::Pending
            }
            Err(RecvError::Disconnected) => Poll::Ready(Err(RecvError::Disconnected)),
        }
    }
}
