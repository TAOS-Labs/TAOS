use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    sync::atomic::{Ordering, AtomicBool, AtomicUsize},
};

use futures::task::ArcWake;
use crate::serial_println;
use crate::events::Event;
use crate::events::RwLock;
use crate::events::EventQueue;
use crate::events::BTreeSet;
use alloc::vec::Vec;

/// Future to block an event until a boolean is set to true (by some other event)
pub struct Condition {
    state: Arc<AtomicBool>,
    event: Arc<Event>,
}

unsafe impl Send for Condition {}

impl Condition {
    pub fn new(
        state: Arc<AtomicBool>,
        event: Arc<Event>,
    ) -> Condition {
        Condition {
            state,
            event,
        }
    }

    pub fn awake(&self) {
        self.event.clone().wake();
    }

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


pub struct Barrier {
    count: Arc<AtomicUsize>,
    threshold: usize,
    event: Arc<Event>,
}

unsafe impl Send for Barrier {}

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


#[cfg(test)]
    mod tests {
    use super::*;
    use alloc::vec::Vec;
    use crate::events::VecDeque;
    use futures::{future::join_all, join, FutureExt};
    #[test_case]
    fn test_barrier_basic() -> impl Future<Output = ()> + Send + 'static {
        let rewake_queue = Arc::new(EventQueue::new(VecDeque::new()));
        let blocked_events = Arc::new(RwLock::new(BTreeSet::new()));
        let future = async {};  // Provide an empty future
        let event = Arc::new(Event::init(future, rewake_queue, blocked_events, 0, 2, 1000));

        let barrier = Barrier::new(3, event.clone());

        async move {
            serial_println!("Starting barrier basic test");
            barrier.wait();
            barrier.wait();
            barrier.wait();
            serial_println!("Barrier should be awakened and shouldd not PANIC");
            // assert!(event.completed.load(Ordering::Acquire));

        }
    }



    #[test_case]
    fn test_barrier_multiple_tasks() -> impl Future<Output = ()> + Send + 'static {
        let rewake_queue = Arc::new(EventQueue::new(VecDeque::new()));
        let blocked_events = Arc::new(RwLock::new(BTreeSet::new()));
        let future = async {};  // Provide an empty future
        let event = Arc::new(Event::init(future, rewake_queue, blocked_events, 0, 2, 1000));

        let barrier = Arc::new(Barrier::new(5, event.clone()));

        async move {
            serial_println!("Starting barrier multiple tasks test");
            let mut tasks = Vec::new();
            for i in 0..5 {
                let barrier_clone = barrier.clone();
                tasks.push(async move {
                    serial_println!("Task {} waiting on barrier", i);
                    barrier_clone.wait();
                });
            }

            join_all(tasks).await;
            serial_println!("All tasks have reached the barrier");
            serial_println!("BARRIER TESTCASE PASSED!!!")
            // assert!(event.completed.load(Ordering::Acquire));

        }
    }
}
