use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use crossbeam_queue::ArrayQueue;

// Not in constants yet because debating about keeping it
const SPIN_LIMIT: u32 = 30;
const BATCH_LIMIT: usize = 32;

#[derive(Debug)]
pub struct AtomicWaker {
    state: AtomicUsize,
    waker: ArrayQueue<Waker>,
}

impl AtomicWaker {
    const EMPTY: usize = 0;
    const REGISTERING: usize = 1;
    const READY: usize = 2;

    fn new() -> Self {
        Self {
            state: AtomicUsize::new(Self::EMPTY),
            waker: ArrayQueue::new(1),
        }
    }

    fn register(&self, waker: &Waker) {
        let state = self.state.load(Ordering::Acquire);
        if state == Self::READY {
            return;
        }

        match self.state.compare_exchange(
            Self::EMPTY,
            Self::REGISTERING,
            Ordering::Acquire,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                let _ = self.waker.pop();
                let _ = self.waker.push(waker.clone());
                self.state.store(Self::READY, Ordering::Release);
            }
            Err(_) => {
                if let Some(existing) = self.waker.pop() {
                    if !existing.will_wake(waker) {
                        let _ = self.waker.push(waker.clone());
                    } else {
                        let _ = self.waker.push(existing);
                    }
                }
            }
        }
    }

    fn wake(&self) {
        if self.state.swap(Self::EMPTY, Ordering::AcqRel) == Self::READY {
            if let Some(waker) = self.waker.pop() {
                waker.wake();
            }
        }
    }
}

#[derive(Debug)]
pub enum SendError<T> {
    Full(T),
    Closed(T),
}

#[derive(Debug)]
pub enum RecvError {
    Empty,
    Closed,
}

#[derive(Debug)]
struct ChannelState {
    senders_waker: AtomicWaker,
    receivers_waker: AtomicWaker,
    sender_count: AtomicUsize,
}

pub struct Channel<T> {
    queue: Arc<ArrayQueue<T>>,
    state: Arc<ChannelState>,
    closed: Arc<AtomicBool>,
}

impl<T> Channel<T> {
    pub fn new(capacity: usize) -> (Sender<T>, Receiver<T>) {
        assert!(capacity > 0, "Channel capacity must be greater than 0");
        let queue = Arc::new(ArrayQueue::new(capacity));
        let state = Arc::new(ChannelState {
            senders_waker: AtomicWaker::new(),
            receivers_waker: AtomicWaker::new(),
            sender_count: AtomicUsize::new(1),
        });
        let closed = Arc::new(AtomicBool::new(false));

        (
            Sender {
                queue: Arc::clone(&queue),
                state: Arc::clone(&state),
                closed: Arc::clone(&closed),
            },
            Receiver {
                queue: Arc::clone(&queue),
                state: Arc::clone(&state),
                closed: Arc::clone(&closed),
            },
        )
    }

    pub fn capacity(&self) -> usize {
        self.queue.capacity()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn sender_count(&self) -> usize {
        self.state.sender_count.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.queue.is_full()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct Sender<T> {
    queue: Arc<ArrayQueue<T>>,
    state: Arc<ChannelState>,
    closed: Arc<AtomicBool>,
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.state.sender_count.fetch_add(1, Ordering::AcqRel);
        Self {
            queue: Arc::clone(&self.queue),
            state: Arc::clone(&self.state),
            closed: Arc::clone(&self.closed),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        if self.state.sender_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.closed.store(true, Ordering::Release);
            self.state.receivers_waker.wake();
        }
    }
}

impl<T> Sender<T> {
    pub fn try_send(&self, value: T) -> Result<(), SendError<T>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(SendError::Closed(value));
        }

        match self.queue.push(value) {
            Ok(()) => {
                if self.queue.len() <= 1 {
                    self.state.receivers_waker.wake();
                }
                Ok(())
            }
            Err(value) => Err(SendError::Full(value)),
        }
    }

    pub fn send(&self, value: T) -> SendFuture<'_, T> {
        SendFuture {
            sender: self,
            value: Some(value),
            spin_count: 0,
        }
    }

    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.state.senders_waker.wake();
            self.state.receivers_waker.wake();
        }
    }
}

#[derive(Debug)]
pub struct Receiver<T> {
    queue: Arc<ArrayQueue<T>>,
    state: Arc<ChannelState>,
    closed: Arc<AtomicBool>,
}

impl<T> Receiver<T> {
    pub fn try_recv(&self) -> Result<T, RecvError> {
        match self.queue.pop() {
            Some(value) => {
                self.state.senders_waker.wake();
                Ok(value)
            }
            None => {
                if self.closed.load(Ordering::Acquire) {
                    Err(RecvError::Closed)
                } else {
                    Err(RecvError::Empty)
                }
            }
        }
    }

    pub fn recv(&self) -> RecvFuture<'_, T> {
        RecvFuture {
            receiver: self,
            spin_count: 0,
        }
    }

    pub fn try_recv_batch(&self, buf: &mut alloc::vec::Vec<T>) -> Result<usize, RecvError> {
        let mut count = 0;
        while let Ok(item) = self.try_recv() {
            buf.push(item);
            count += 1;
            if count >= BATCH_LIMIT {
                break;
            }
        }
        if count > 0 {
            Ok(count)
        } else if self.closed.load(Ordering::Acquire) {
            Err(RecvError::Closed)
        } else {
            Err(RecvError::Empty)
        }
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.queue.is_full()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

pub struct SendFuture<'a, T> {
    sender: &'a Sender<T>,
    value: Option<T>,
    spin_count: u32,
}

impl<'a, T> Future for SendFuture<'a, T> {
    type Output = Result<(), SendError<T>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if this.sender.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(SendError::Closed(
                this.value.take().expect("polled after completion"),
            )));
        }

        let value = this.value.take().expect("polled after completion");

        match this.sender.try_send(value) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(SendError::Full(value)) => {
                if this.spin_count < SPIN_LIMIT {
                    this.value = Some(value);
                    this.spin_count += 1;
                    spin_wait(this.spin_count);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    this.value = Some(value);
                    this.sender.state.senders_waker.register(cx.waker());
                    Poll::Pending
                }
            }
            Err(SendError::Closed(value)) => Poll::Ready(Err(SendError::Closed(value))),
        }
    }
}

pub struct RecvFuture<'a, T> {
    receiver: &'a Receiver<T>,
    spin_count: u32,
}

impl<'a, T> Future for RecvFuture<'a, T> {
    type Output = Result<T, RecvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        match this.receiver.try_recv() {
            Ok(value) => Poll::Ready(Ok(value)),
            Err(RecvError::Empty) => {
                if this.receiver.closed.load(Ordering::Acquire) {
                    Poll::Ready(Err(RecvError::Closed))
                } else if this.spin_count < SPIN_LIMIT {
                    this.spin_count += 1;
                    spin_wait(this.spin_count);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    this.receiver.state.receivers_waker.register(cx.waker());
                    Poll::Pending
                }
            }
            Err(RecvError::Closed) => Poll::Ready(Err(RecvError::Closed)),
        }
    }
}

#[inline]
fn spin_wait(spin_count: u32) {
    match spin_count {
        0..=10 => core::hint::spin_loop(),
        11..=20 => {
            for _ in 0..spin_count {
                core::hint::spin_loop()
            }
        }
        _ => {
            for _ in 0..100 {
                core::hint::spin_loop()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::String, vec, vec::Vec};
    use futures::future::join_all;
    use futures::{join, FutureExt};

    async fn spin_future() {
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }

    #[test_case]
    fn test_basic_operations() -> impl Future<Output = ()> + Send + 'static {
        let (tx, rx) = Channel::new(2);

        async move {
            assert_eq!(tx.queue.capacity(), 2);
            assert!(rx.is_empty());
            assert!(!rx.is_full());
            assert!(!rx.is_closed());

            tx.send(1).await.unwrap();
            assert_eq!(rx.len(), 1);
            tx.send(2).await.unwrap();
            assert_eq!(rx.len(), 2);
            assert!(rx.is_full());

            assert_eq!(rx.recv().await.unwrap(), 1);
            assert_eq!(rx.recv().await.unwrap(), 2);
            assert!(rx.is_empty());
        }
    }

    #[test_case]
    fn test_send_recv_ordering() -> impl Future<Output = ()> + Send + 'static {
        let (tx, rx) = Channel::new(100);

        async move {
            for i in 0..100 {
                tx.send(i).await.unwrap();
            }

            for i in 0..100 {
                assert_eq!(rx.recv().await.unwrap(), i);
            }
        }
    }

    #[test_case]
    fn test_multiple_producers() -> impl Future<Output = ()> + Send + 'static {
        let (tx, rx) = Channel::new(100);

        async move {
            let mut senders = Vec::new();
            let mut expected_sum = 0;

            for i in 0..10 {
                let tx = tx.clone();
                expected_sum += i;
                senders.push(async move {
                    tx.send(i).await.unwrap();
                });
            }

            join_all(senders).await;

            let mut sum = 0;
            for _ in 0..10 {
                sum += rx.recv().await.unwrap();
            }

            assert_eq!(sum, expected_sum);
        }
    }

    #[test_case]
    fn test_multiple_producers_full_channel() -> impl Future<Output = ()> + Send + 'static {
        let (tx, rx) = Channel::new(5);

        async move {
            let mut senders = Vec::new();

            for i in 0..10 {
                let tx = tx.clone();
                senders.push(async move {
                    tx.send(i).await.unwrap();
                });
            }

            let send_fut = join_all(senders).fuse();
            let recv_fut = async {
                let mut received = Vec::new();
                for _ in 0..10 {
                    received.push(rx.recv().await.unwrap());
                }
                received
            }
            .fuse();

            let (_, received) = join!(send_fut, recv_fut);

            assert_eq!(received.len(), 10);
            for i in 0..10 {
                assert!(received.contains(&i));
            }
        }
    }

    #[test_case]
    fn test_batch_operations() -> impl Future<Output = ()> + Send + 'static {
        let (tx, rx) = Channel::new(100);

        async move {
            for i in 0..50 {
                tx.send(i).await.unwrap();
            }

            let mut buf = Vec::new();
            let count = rx.try_recv_batch(&mut buf).unwrap();
            assert_eq!(count, 32);

            for i in 0..32 {
                assert_eq!(buf[i], i);
            }

            for i in 32..50 {
                assert_eq!(rx.recv().await.unwrap(), i);
            }
        }
    }

    #[test_case]
    fn test_close_behavior() -> impl Future<Output = ()> + Send + 'static {
        let (tx, rx) = Channel::new(10);

        async move {
            tx.send(1).await.unwrap();
            tx.send(2).await.unwrap();

            tx.close();
            assert!(rx.is_closed());

            assert_eq!(rx.recv().await.unwrap(), 1);
            assert_eq!(rx.recv().await.unwrap(), 2);

            assert!(matches!(rx.recv().await, Err(RecvError::Closed)));

            assert!(matches!(tx.send(3).await, Err(SendError::Closed(3))));
        }
    }

    #[test_case]
    fn test_drop_behavior() -> impl Future<Output = ()> + Send + 'static {
        let (tx, rx) = Channel::new(10);

        async move {
            let tx2 = tx.clone();

            tx.send(1).await.unwrap();
            tx2.send(2).await.unwrap();

            drop(tx);

            tx2.send(3).await.unwrap();
            assert_eq!(rx.recv().await.unwrap(), 1);
            assert_eq!(rx.recv().await.unwrap(), 2);
            assert_eq!(rx.recv().await.unwrap(), 3);

            drop(tx2);

            assert!(matches!(rx.recv().await, Err(RecvError::Closed)));
        }
    }

    #[test_case]
    fn test_zero_sized_type() -> impl Future<Output = ()> + Send + 'static {
        let (tx, rx) = Channel::new(10);

        async move {
            tx.send(()).await.unwrap();
            assert_eq!(rx.recv().await.unwrap(), ());
        }
    }

    #[test_case]
    fn test_concurrent_channels() -> impl Future<Output = ()> + Send + 'static {
        let (tx1, rx1) = Channel::new(1);
        let (tx2, rx2) = Channel::new(1);

        async move {
            let send_fut1 = async {
                spin_future().await;
                tx1.send(1).await.unwrap();
            }
            .fuse();

            let send_fut2 = async {
                spin_future().await;
                tx2.send(2).await.unwrap();
            }
            .fuse();

            let recv_fut1 = rx1.recv().fuse();
            let recv_fut2 = rx2.recv().fuse();
            let ((), (), v1, v2) = join!(send_fut1, send_fut2, recv_fut1, recv_fut2);

            assert_eq!(v1.unwrap(), 1);
            assert_eq!(v2.unwrap(), 2);
        }
    }

    #[test_case]
    fn test_try_operations() -> impl Future<Output = ()> + Send + 'static {
        let (tx, rx) = Channel::new(2);

        async move {
            assert!(tx.try_send(1).is_ok());
            assert!(tx.try_send(2).is_ok());
            assert!(matches!(tx.try_send(3), Err(SendError::Full(3))));

            assert_eq!(rx.try_recv().unwrap(), 1);
            assert_eq!(rx.try_recv().unwrap(), 2);
            assert!(matches!(rx.try_recv(), Err(RecvError::Empty)));
        }
    }
}
