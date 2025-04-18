use alloc::{sync::Arc, vec::Vec};
use core::{
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll},
};
use spin::RwLock;

use futures::task::ArcWake;

use crate::events::{current_running_event, Event};

/// Future to block an event until a boolean is set to true (by some other event)
pub struct Condition {
    /// Ready or not
    state: Arc<AtomicBool>,
    /// The event to block on
    event: Arc<Event>,
}

unsafe impl Send for Condition {}

impl Condition {
    /// Create a new Condition
    ///
    /// * `state`: the starting state
    /// * `event`: the relevant event
    pub fn new(state: Arc<AtomicBool>, event: Arc<Event>) -> Condition {
        Condition { state, event }
    }

    /// The associated event is ready to make progress
    pub fn awake(&self) {
        self.event.clone().wake();
    }

    /// Returns the associated event id
    pub fn get_id(&self) -> u64 {
        self.event.eid.0
    }
}

impl Future for Condition {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if self.state.load(Ordering::Relaxed) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

#[deprecated(note = "Needs updating to event system")]
pub struct Barrier {
    count: Arc<AtomicUsize>,
    threshold: usize,
    event: Arc<Event>,
}

#[allow(deprecated)]
unsafe impl Send for Barrier {}

#[allow(deprecated)]
impl Barrier {
    pub fn new(threshold: usize, event: Arc<Event>) -> Barrier {
        Barrier {
            count: Arc::new(AtomicUsize::new(0)),
            threshold,
            event,
        }
    }

    pub fn wait(&self) {
        let prev = self.count.fetch_add(1, Ordering::AcqRel);
        if prev + 1 == self.threshold {
            self.event.clone().wake();
        }
    }
}

#[allow(deprecated)]
impl Future for Barrier {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if self.count.load(Ordering::Acquire) >= self.threshold {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

pub struct BoundedBuffer<T> {
    buffer: RwLock<Vec<Option<T>>>,
    capacity: usize,
    count: AtomicUsize,
    head: AtomicUsize,
    tail: AtomicUsize,
    get_event: Arc<Event>,
    put_event: Arc<Event>,
}

impl<T> BoundedBuffer<T> {
    pub fn new(capacity: usize, get_event: Arc<Event>, put_event: Arc<Event>) -> Self {
        let mut buf = Vec::with_capacity(capacity);
        buf.resize_with(capacity, || None);
        Self {
            buffer: RwLock::new(buf),
            capacity,
            count: AtomicUsize::new(0),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            get_event,
            put_event,
        }
    }

    pub fn put(&self, value: T) {
        while self.count.load(Ordering::Acquire) == self.capacity {}

        let tail = self.tail.load(Ordering::Relaxed) % self.capacity;
        {
            let mut buf = self.buffer.write();
            buf[tail] = Some(value);
        }

        self.tail.fetch_add(1, Ordering::Release);
        self.count.fetch_add(1, Ordering::Release);
        self.get_event.clone().wake(); // Wake up any `get` tasks
    }

    pub fn get(&self) -> Option<T> {
        while self.count.load(Ordering::Acquire) == 0 {}

        let head = self.head.load(Ordering::Relaxed) % self.capacity;
        let val = {
            let mut buf = self.buffer.write();
            buf[head].take()
        };

        self.head.fetch_add(1, Ordering::Release);
        self.count.fetch_sub(1, Ordering::Release);
        self.put_event.clone().wake();

        val
    }
}

pub struct BlockMutex<T> {
    unlocked: Arc<AtomicBool>,
    data: T,
}

unsafe impl<T> Send for BlockMutex<T> {}
unsafe impl<T> Sync for BlockMutex<T> {}

impl<T> BlockMutex<T> {
    pub fn new(data: T) -> BlockMutex<T> {
        BlockMutex {
            unlocked: Arc::new(AtomicBool::new(true)),
            data,
        }
    }

    pub async fn lock(&mut self) -> BlockMutexGuard<T> {
        let event = current_running_event().expect("Using BlockMutex outside event");
        Condition::new(self.unlocked.clone(), event).await;

        self.unlocked.store(false, Ordering::Relaxed);

        BlockMutexGuard { mutex: self }
    }

    fn unlock(&mut self) {
        self.unlocked.store(true, Ordering::Relaxed);
    }
}

pub struct BlockMutexGuard<'a, T> {
    mutex: &'a mut BlockMutex<T>,
}

impl<T> Deref for BlockMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.mutex.data
    }
}

impl<T> DerefMut for BlockMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mutex.data
    }
}

impl<T> Drop for BlockMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.unlock();
    }
}
