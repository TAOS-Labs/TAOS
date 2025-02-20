use super::{Event, EventQueue, EventRunner};

use alloc::{
    collections::{btree_set::BTreeSet, vec_deque::VecDeque},
    sync::Arc,
};
use futures::task::waker_ref;
use spin::rwlock::RwLock;
use x86_64::instructions::interrupts;

use core::{
    future::Future,
    sync::atomic::Ordering,
    task::{Context, Poll, Waker},
};

use super::{
    tasks::{CancellationToken, JoinHandle, TaskError},
    EventId,
};
use crate::constants::events::NUM_EVENT_PRIORITIES;
use spin::Mutex;

use crate::constants::events::PRIORITY_INC_DELAY;

impl EventRunner {
    pub fn init() -> EventRunner {
        EventRunner {
            event_queues: core::array::from_fn(|_| RwLock::new(VecDeque::new())),
            rewake_queue: Arc::new(RwLock::new(VecDeque::new())),
            pending_events: RwLock::new(BTreeSet::new()),
            current_event: None,
            clock: 0,
        }
    }

    pub fn run_loop(&mut self) -> ! {
        loop {
            loop {
                if self.have_pending_events() {
                    break;
                }

                self.current_event = self.next_event();

                let event = self
                    .current_event
                    .as_ref()
                    .expect("Have pending events, but empty waiting queues.");

                if self.contains_event(event.eid) {
                    self.clock += 1;

                    let waker = waker_ref(event);
                    let mut context: Context<'_> = Context::from_waker(&waker);

                    let mut future_guard = event.future.lock();

                    let ready: bool = future_guard.as_mut().poll(&mut context) != Poll::Pending;

                    drop(future_guard);

                    if !ready {
                        let priority = event.priority.load(Ordering::Relaxed);
                        Self::enqueue(&self.event_queues[priority], event.clone());
                    } else {
                        let mut write_lock = self.pending_events.write();
                        write_lock.remove(&event.eid.0);
                    }
                }

                self.current_event = None;
            }

            // TODO do a lil work-stealing

            interrupts::enable_and_hlt();
        }
    }

    // Schedules an event with a specified priority level [0, NUM_EVENT_PRIORITIES)
    pub fn schedule(
        &mut self,
        future: impl Future<Output = ()> + 'static + Send,
        priority_level: usize,
        pid: u32,
    ) {
        if priority_level >= NUM_EVENT_PRIORITIES {
            panic!("Invalid event priority: {}", priority_level);
        } else {
            let event = Arc::new(Event::init(
                future,
                self.rewake_queue.clone(),
                priority_level,
                pid,
                self.clock,
            ));

            Self::enqueue(&self.event_queues[priority_level], event.clone());

            let mut write_lock = self.pending_events.write();

            write_lock.insert(event.eid.0);
        }
    }

    pub fn current_running_event(&self) -> Option<&Arc<Event>> {
        self.current_event.as_ref()
    }

    pub fn spawn<F, T>(&mut self, future: F, priority_level: usize) -> JoinHandle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let result: Arc<Mutex<Option<Result<T, TaskError>>>> = Arc::new(Mutex::new(None));
        let waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
        let cancellation = CancellationToken::new();

        // Wrap the future to store its result and handle cancellation
        let wrapped_future = {
            let result = result.clone();
            let waker = waker.clone();
            let cancellation = cancellation.clone();

            async move {
                let output = match future.await {
                    output => {
                        if cancellation.is_cancelled() {
                            Err(TaskError::Cancelled)
                        } else {
                            Ok(output)
                        }
                    }
                };

                // Store the result
                *result.lock() = Some(output);

                // Wake up anyone waiting on the join handle
                if let Some(waker) = waker.lock().take() {
                    waker.wake();
                }
            }
        };

        // Schedule the wrapped future
        self.schedule(wrapped_future, priority_level, 0);

        JoinHandle {
            result,
            waker,
            eid: EventId::init(),
            cancellation,
        }
    }

    fn have_pending_events(&self) -> bool {
        self.pending_events.read().is_empty()
    }

    fn contains_event(&self, eid: EventId) -> bool {
        self.pending_events.read().contains(&eid.0)
    }

    fn front_clock(queue: &EventQueue) -> Option<u64> {
        queue
            .read()
            .front()
            .map(|e| e.scheduled_clock.load(Ordering::Relaxed))
    }

    fn try_pop(queue: &EventQueue) -> Option<Arc<Event>> {
        queue.write().pop_front()
    }

    fn enqueue(queue: &EventQueue, event: Arc<Event>) {
        queue.write().push_back(event);
    }

    fn reprioritize(&mut self) {
        for i in 1..NUM_EVENT_PRIORITIES {
            let scheduled_clock = Self::front_clock(&self.event_queues[i]);

            scheduled_clock.inspect(|event_scheduled_at| {
                if event_scheduled_at + PRIORITY_INC_DELAY <= self.clock {
                    let event_to_move = Self::try_pop(&self.event_queues[i]);
                    event_to_move.inspect(|e| {
                        Self::enqueue(&self.event_queues[i - 1], e.clone());

                        e.priority.swap(i - 1, Ordering::Relaxed);
                        e.scheduled_clock.swap(self.clock, Ordering::Relaxed);
                    });
                }
            });
        }
    }

    fn next_event(&mut self) -> Option<Arc<Event>> {
        let rewake = Self::try_pop(&self.rewake_queue);
        if rewake.is_some() {
            rewake
        } else {
            let mut event = None;

            self.reprioritize();

            for i in 0..NUM_EVENT_PRIORITIES {
                event = Self::try_pop(&self.event_queues[i]);
                if event.is_some() {
                    break;
                }
            }

            event
        }
    }
}
