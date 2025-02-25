use alloc::{
    collections::{binary_heap::BinaryHeap, btree_set::BTreeSet, vec_deque::VecDeque},
    sync::Arc,
};
use futures::task::waker_ref;
use spin::rwlock::RwLock;
use x86_64::instructions::interrupts::{self, without_interrupts};

use core::{
    future::Future,
    sync::atomic::Ordering,
    task::{Context, Poll, Waker},
};

use super::{
    futures::Sleep, tasks::{CancellationToken, JoinHandle, TaskError}, Event, EventId, EventQueue, EventRunner
};
use crate::{constants::events::NUM_EVENT_PRIORITIES, interrupts::x2apic::nanos_to_ticks, serial_println};
use spin::Mutex;

use crate::constants::events::PRIORITY_INC_DELAY;

impl EventRunner {
    pub fn init() -> EventRunner {
        EventRunner {
            event_queues: core::array::from_fn(|_| Arc::new(RwLock::new(VecDeque::new()))),
            pending_events: RwLock::new(BTreeSet::new()),
            sleeping_events: BinaryHeap::new(),
            current_event: None,
            event_clock: 0,
            system_clock: 0,
        }
    }

    pub fn run_loop(&mut self) -> ! {
        loop {
            loop {
                if !self.have_unblocked_events() {
                    break;
                }

                self.current_event = self.next_event();

                let event = self
                    .current_event
                    .as_ref()
                    .expect("Have pending events, but empty waiting queues.");

                if self.contains_event(event.eid) {
                    self.event_clock += 1;

                    let waker = waker_ref(event);
                    let mut context: Context<'_> = Context::from_waker(&waker);

                    let mut future_guard = event.future.lock();

                    let ready: bool = future_guard.as_mut().poll(&mut context) != Poll::Pending;

                    drop(future_guard);

                    if !ready {
                        let priority = event.priority.load(Ordering::Relaxed);
                        event
                            .scheduled_timestamp
                            .swap(self.event_clock, Ordering::Relaxed);
                        Self::enqueue(&self.event_queues[priority], event.clone());
                    } else {
                        self.pending_events.write().remove(&event.eid.0);
                    }
                }

                self.current_event = None;
            }

            // TODO do a lil work-stealing

            // Must have pending, but blocked, events
            if self.have_pending_events() {
                self.awake_next_sleeper();
            }

            interrupts::enable_and_hlt();
        }
    }

    // Schedules an event with a specified priority level [0, NUM_EVENT_PRIORITIES)
    pub fn schedule(
        &mut self,
        future: impl Future<Output = ()> + 'static + Send,
        priority_level: usize,
        pid: u32,
    ) -> Option<EventId> {
        if priority_level >= NUM_EVENT_PRIORITIES {
            panic!("Invalid event priority: {}", priority_level);
        } else {
            let event = Arc::new(Event::init(
                future,
                self.event_queues[priority_level].clone(),
                priority_level,
                pid,
                self.event_clock,
            ));

            Self::enqueue(&self.event_queues[priority_level], event.clone());

            self.pending_events.write().insert(event.eid.0);

            serial_println!("Scheduled {}", event.eid.0);
            serial_println!("{} pending", self.pending_events.read().len());

            Some(event.eid)
        }
    }

    pub fn current_running_event(&self) -> Option<&Arc<Event>> {
        self.current_event.as_ref()
    }


    pub fn inc_system_clock(&mut self) {
        self.system_clock += 1;
    }

    pub fn awake_next_sleeper(&mut self) {
        let sleeper = self.sleeping_events.peek();

        if sleeper.is_some() {
            let future = sleeper.unwrap();
            if future.target_timestamp <= self.system_clock {
                future.awake();
                self.sleeping_events.pop();
            }
        }
    }

    pub fn nanosleep_current_event(&mut self, nanos: u64) -> Option<Sleep> {
        self.current_event.as_ref().map(|e| {
            let system_ticks = nanos_to_ticks(nanos);

            let sleep = Sleep::new(self.system_clock + system_ticks, (*e).clone());
            self.sleeping_events.push(sleep.clone());

            sleep
        })
    }

    pub fn nanosleep_event(
        &mut self, 
        future: impl Future<Output = ()> + 'static + Send,
        priority_level: usize,
        pid: u32,
        nanos: u64
    ) -> Option<Sleep> {
        if priority_level >= NUM_EVENT_PRIORITIES {
            panic!("Invalid event priority: {}", priority_level);
        } else {
            let event = Arc::new(Event::init(
                future,
                self.event_queues[priority_level].clone(),
                priority_level,
                pid,
                self.event_clock,
            ));

            let system_ticks = nanos_to_ticks(nanos);

            let sleep = Sleep::new(self.system_clock + system_ticks, event.clone());
            self.sleeping_events.push(sleep.clone());

            self.pending_events.write().insert(event.eid.0);

            Some(sleep)
        }
    }

    pub fn spawn<F, T>(&mut self, future: F, priority_level: usize) -> JoinHandle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        without_interrupts(|| {
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
            let eid = without_interrupts(|| {
                self.schedule(wrapped_future, priority_level, 0)
            });
            
            JoinHandle {
                result,
                waker,
                eid: eid.unwrap(),
                cancellation,
            }
        })
    }

    fn have_pending_events(&self) -> bool {
        !self.pending_events.read().is_empty()
    }

    fn have_unblocked_events(&self) -> bool {
        for queue in self.event_queues.iter() {
            if !queue.read().is_empty() {
                return true;
            }
        }

        false
    }

    fn contains_event(&self, eid: EventId) -> bool {
        self.pending_events.read().contains(&eid.0)
    }

    fn next_event_timestamp(queue: &EventQueue) -> Option<u64> {
        queue
            .read()
            .front()
            .map(|e| e.scheduled_timestamp.load(Ordering::Relaxed))
    }

    fn try_pop(queue: &EventQueue) -> Option<Arc<Event>> {
        queue.write().pop_front()
    }

    fn enqueue(queue: &EventQueue, event: Arc<Event>) {
        queue.write().push_back(event);
    }

    fn reprioritize(&mut self) {
        for i in 1..NUM_EVENT_PRIORITIES {
            let scheduled_clock = Self::next_event_timestamp(&self.event_queues[i]);

            scheduled_clock.inspect(|event_scheduled_at| {
                if event_scheduled_at + PRIORITY_INC_DELAY <= self.event_clock {
                    let event_to_move = Self::try_pop(&self.event_queues[i]);
                    event_to_move.inspect(|e| {
                        Self::enqueue(&self.event_queues[i - 1], e.clone());
                        
                        Self::change_priority(&e, i-1);
                        e.scheduled_timestamp
                            .swap(self.event_clock, Ordering::Relaxed);
                    });
                }
            });
        }
    }

    fn change_priority(event: &Event, priority: usize) {
        event.priority.swap(priority, Ordering::Relaxed);
    }

    fn next_event(&mut self) -> Option<Arc<Event>> {
        self.awake_next_sleeper();

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
