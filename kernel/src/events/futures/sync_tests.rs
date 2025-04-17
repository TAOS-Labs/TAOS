use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll},
};

use crate::{
    events::{BTreeSet, Event, EventQueue, RwLock},
    serial_println,
};
use alloc::vec::Vec;
use futures::task::ArcWake;

use crate::events::futures::sync::Barrier;

use crate::events::futures::sync::BoundedBuffer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        debug,
        events::{
            current_running_event,
            futures::{await_on::Await, sync::BlockMutex},
            get_runner_time, nanosleep_current_event, schedule_kernel, VecDeque,
        },
    };
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use futures::{future::join_all, join, FutureExt};

    // #[test_case]
    fn test_barrier_basic() -> impl Future<Output = ()> + Send + 'static {
        let rewake_queue = Arc::new(EventQueue::new(VecDeque::new()));
        let blocked_events = Arc::new(RwLock::new(BTreeSet::new()));
        let future = async {}; // Provide an empty future
        let event = Arc::new(Event::init(
            future,
            rewake_queue,
            blocked_events,
            0,
            2,
            1000,
        ));

        let barrier = Barrier::new(3, event.clone());

        async move {
            debug!("Starting barrier basic test");
            barrier.wait();
            barrier.wait();
            barrier.wait();
            debug!("Barrier should be awakened and should not PANIC");
            assert!(event.completed.load(Ordering::Acquire));
        }
    }

    // #[test_case]
    fn test_barrier_multiple_tasks() -> impl Future<Output = ()> + Send + 'static {
        let rewake_queue = Arc::new(EventQueue::new(VecDeque::new()));
        let blocked_events = Arc::new(RwLock::new(BTreeSet::new()));
        let future = async {}; // Provide an empty future
        let event = Arc::new(Event::init(
            future,
            rewake_queue,
            blocked_events,
            0,
            2,
            1000,
        ));

        let barrier = Arc::new(Barrier::new(5, event.clone()));

        async move {
            debug!("Starting barrier multiple tasks test");
            let mut tasks = Vec::new();
            for i in 0..5 {
                let barrier_clone = barrier.clone();
                tasks.push(async move {
                    debug!("Task {} waiting on barrier", i);
                    barrier_clone.wait();
                });
            }

            join_all(tasks).await;
            debug!("All tasks have reached the barrier");
            debug!("BARRIER TESTCASE PASSED!!!");
            assert!(event.completed.load(Ordering::Acquire));
        }
    }

    #[test_case]
    /// running with ints
    fn test_bounded_buffer_basic() -> impl Future<Output = ()> + Send + 'static {
        let q = Arc::new(EventQueue::new(VecDeque::new()));
        let blocked = Arc::new(RwLock::new(BTreeSet::new()));
        let e1 = Arc::new(Event::init(async {}, q.clone(), blocked.clone(), 0, 1, 100));
        let e2 = Arc::new(Event::init(async {}, q.clone(), blocked.clone(), 0, 2, 100));

        let bb = Arc::new(BoundedBuffer::new(2, e1.clone(), e2.clone()));

        async move {
            debug!("Running basic put/get test");
            bb.put(42);
            let val = bb.get().unwrap();
            assert_eq!(val, 42);
            debug!("Basic bounded buffer test passed!");
        }
    }

    #[test_case]
    /// to see if they will work toggether
    fn test_bounded_buffer_concurrent() -> impl Future<Output = ()> + Send + 'static {
        let q = Arc::new(EventQueue::new(VecDeque::new()));
        let blocked = Arc::new(RwLock::new(BTreeSet::new()));
        let get_e = Arc::new(Event::init(async {}, q.clone(), blocked.clone(), 0, 3, 100));
        let put_e = Arc::new(Event::init(async {}, q.clone(), blocked.clone(), 0, 4, 100));

        let bb = Arc::new(BoundedBuffer::new(3, get_e.clone(), put_e.clone()));

        async move {
            let producers: Vec<_> = (0..3)
                .map(|i| {
                    let bb_clone = bb.clone();
                    async move {
                        bb_clone.put(i);
                        debug!("Put {}", i);
                    }
                })
                .collect();

            let consumers: Vec<_> = (0..3)
                .map(|_| {
                    let bb_clone = bb.clone();
                    async move {
                        let val = bb_clone.get().unwrap();
                        debug!("Got {}", val);
                    }
                })
                .collect();

            join_all(producers).await;
            join_all(consumers).await;
            debug!("Concurrent test passed!");
        }
    }

    #[test_case]
    /// addded an event testcase to
    fn test_event_in_bounded_buffer() -> impl Future<Output = ()> + Send + 'static {
        use crate::events::{EventQueue, VecDeque};

        async move {
            debug!("Sttarting test_event_in_bounded_buffer");

            let rewake_queue = Arc::new(EventQueue::new(VecDeque::new()));
            let blocked_events = Arc::new(RwLock::new(BTreeSet::new()));

            let event1 = Arc::new(Event::init(
                async {},
                rewake_queue.clone(),
                blocked_events.clone(),
                0,
                1,
                100,
            ));
            let event2 = Arc::new(Event::init(
                async {},
                rewake_queue.clone(),
                blocked_events.clone(),
                0,
                2,
                200,
            ));
            let event1_id = event1.eid.0;
            let event2_id = event2.eid.0;

            let buffer = Arc::new(BoundedBuffer::new(2, event1.clone(), event2.clone()));

            buffer.put(event1.clone());
            buffer.put(event2.clone());

            serial_println!("Put 2 events into the buffer");

            let retrieved1 = buffer.get().unwrap();
            let retrieved2 = buffer.get().unwrap();

            debug!("Retrieve 2 events from the buffer");

            // Check they match what was put in (by event ID?)
            assert_eq!(retrieved1.eid.0, event1_id);
            assert_eq!(retrieved2.eid.0, event2_id);

            // wakke up
            retrieved1.clone().wake();
            retrieved2.clone().wake();

            debug!("Event in bbuffer test passed!");
        }
    }

    static mut MUTEX: Option<BlockMutex<i32>> = None;

    #[test_case]
    async fn test_mutex() {
        unsafe { MUTEX.replace(BlockMutex::new(10)) };

        // This event should acquire the lock first and perform 10 + 5 = 5
        let write_event = schedule_kernel(
            async {
                let mut val = unsafe { MUTEX.as_mut().unwrap().lock().await };
                nanosleep_current_event(20_000_000).unwrap().await;

                *val += 5;
            },
            1,
        );

        // This event should acquire the lock second and read 15
        let read_event = schedule_kernel(
            async {
                nanosleep_current_event(5_000_000).unwrap().await;
                let val = unsafe { MUTEX.as_mut().unwrap().lock().await };

                assert_eq!(*val, 15);
            },
            1,
        );

        let write_res = Await::new(
            write_event,
            get_runner_time(100_000_000),
            current_running_event().unwrap(),
        )
        .await;

        assert_eq!(write_res.is_ok(), true);

        let read_res = Await::new(
            read_event,
            get_runner_time(100_000_000),
            current_running_event().unwrap(),
        )
        .await;

        assert_eq!(read_res.is_ok(), true);
    }
}
