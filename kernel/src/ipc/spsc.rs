use alloc::{boxed::Box, vec::Vec};
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

pub const SPSC_DEFAULT_CAPACITY: usize = 32;

pub struct SpscChannel<T> {
    buffer: Box<[UnsafeCell<MaybeUninit<T>>]>,
    capacity: usize,
    head: AtomicUsize, // Consumer reads from head
    tail: AtomicUsize, // Producer writes to tail
    rx_waker: UnsafeCell<Option<Waker>>,
    tx_waker: UnsafeCell<Option<Waker>>,
    is_dropped: AtomicUsize,
}

const NOT_DROPPED: usize = 0;
const SENDER_DROPPED: usize = 1;
const RECEIVER_DROPPED: usize = 2;

unsafe impl<T: Send> Send for SpscChannel<T> {}
unsafe impl<T: Send> Sync for SpscChannel<T> {}

pub struct Sender<T> {
    channel: *const SpscChannel<T>,
}

pub struct Receiver<T> {
    channel: *const SpscChannel<T>,
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
        let channel = Box::leak(Box::new(self));
        (Sender { channel }, Receiver { channel })
    }

    unsafe fn cleanup(&self, start: usize, end: usize) {
        for i in start..end {
            let idx = i % self.capacity;
            (*self.buffer[idx].get()).assume_init_drop();
        }
    }
}

impl<T> Sender<T> {
    pub fn try_send(&self, value: T) -> Result<(), SendError<T>> {
        let channel = unsafe { &*self.channel };

        // Check if receiver is dropped
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

            // Wake receiver if it's waiting
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
        let channel = unsafe { &*self.channel };
        let head = channel.head.load(Ordering::Acquire);
        let tail = channel.tail.load(Ordering::Acquire);

        if head != tail {
            let value =
                unsafe { (*channel.buffer[head % channel.capacity].get()).assume_init_read() };
            channel.head.store(head.wrapping_add(1), Ordering::Release);

            // Wake sender if it's waiting
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
        let channel = unsafe { &*self.channel };
        channel
            .is_dropped
            .fetch_or(SENDER_DROPPED, Ordering::AcqRel);

        if let Some(waker) = unsafe { (*channel.rx_waker.get()).take() } {
            waker.wake();
        }

        if channel.is_dropped.load(Ordering::Acquire) & RECEIVER_DROPPED != 0 {
            let head = channel.head.load(Ordering::Acquire);
            let tail = channel.tail.load(Ordering::Acquire);
            unsafe {
                channel.cleanup(head, tail);
                drop(Box::from_raw(self.channel as *mut SpscChannel<T>));
            }
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let channel = unsafe { &*self.channel };
        channel
            .is_dropped
            .fetch_or(RECEIVER_DROPPED, Ordering::AcqRel);

        if let Some(waker) = unsafe { (*channel.tx_waker.get()).take() } {
            waker.wake();
        }

        if channel.is_dropped.load(Ordering::Acquire) & SENDER_DROPPED != 0 {
            let head = channel.head.load(Ordering::Acquire);
            let tail = channel.tail.load(Ordering::Acquire);
            unsafe {
                channel.cleanup(head, tail);
                drop(Box::from_raw(self.channel as *mut SpscChannel<T>));
            }
        }
    }
}

pub struct SendFuture<'a, T> {
    sender: &'a Sender<T>,
    value: Option<T>,
}

impl<'a, T> Future for SendFuture<'a, T> {
    type Output = Result<(), SendError<T>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        let value = this.value.take().expect("polled after completion");

        match this.sender.try_send(value) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(SendError::Full(value)) => {
                this.value = Some(value);

                unsafe {
                    *(*this.sender.channel).tx_waker.get() = Some(cx.waker().clone());
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

impl<'a, T> Future for RecvFuture<'a, T> {
    type Output = Result<T, RecvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.receiver.try_recv() {
            Ok(value) => Poll::Ready(Ok(value)),
            Err(RecvError::Empty) => {
                unsafe {
                    *(*self.receiver.channel).rx_waker.get() = Some(cx.waker().clone());
                }
                Poll::Pending
            }
            Err(RecvError::Disconnected) => Poll::Ready(Err(RecvError::Disconnected)),
        }
    }
}
