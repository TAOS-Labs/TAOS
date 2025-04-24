use super::{
    futures::sleep::Sleep,
    tasks::{CancellationToken, TaskError},
    Event, EventId, EventQueue, EventRunner, JoinHandle,
};

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

use crate::{
    constants::events::{NUM_EVENT_PRIORITIES, PRIORITY_INC_DELAY},
    interrupts::x2apic::nanos_to_ticks, serial_println,
};
use spin::Mutex;

impl EventRunner {
    pub fn init() -> EventRunner {
        EventRunner {
            event_queues: core::array::from_fn(|_| Arc::new(RwLock::new(VecDeque::new()))),
            pending_events: RwLock::new(BTreeSet::new()),
            blocked_events: Arc::new(RwLock::new(BTreeSet::new())),
            sleeping_events: BinaryHeap::new(),
            current_event: None,
            event_clock: 0,
            system_clock: 0,
        }
    }

    /// Continuously runs events/process on a core
    pub fn run_loop(&mut self) -> ! {
        // Run -> halt -> run -> ... loop
        loop {
            // Loop to run pending events
            loop {
                if !self.have_unblocked_events() {
                    break;
                }

                self.current_event = self.next_event();

                let event = self
                    .current_event
                    .as_ref()
                    .expect("Have pending events, but empty waiting queues.");

                // If not contained, then event must've been completed and
                // rescheduled (likely due to multiple wakes)
                if self.contains_event(event.eid) {
                    self.event_clock += 1;

                    let waker = waker_ref(event);
                    let mut context: Context<'_> = Context::from_waker(&waker);

                    let mut future_guard = event.future.lock();

                    // Executes the event
                    let ready: bool = future_guard.as_mut().poll(&mut context) != Poll::Pending;

                    drop(future_guard);

                    if !ready {
                        // Mark event as having been executed recently
                        event
                            .scheduled_timestamp
                            .swap(self.event_clock, Ordering::Relaxed);

                        // Reschedule the event if it isn't blocked
                        if !self.blocked_events.read().contains(&event.eid.0) {
                            let priority = event.priority.load(Ordering::Relaxed);
                            Self::enqueue(&self.event_queues[priority], event.clone());
                        }
                    } else {
                        // Event is ready, go ahead and remove it
                        event.completed.swap(true, Ordering::Relaxed);
                        self.pending_events.write().remove(&event.eid.0);

                        crate::debug!("Event {} done", event.eid.0);
                    }
                }

                self.current_event = None;

                // Explicitly re-enable interrupts once the current event is unmarked
                // Helps with run_process_ring3(), which shouldn't be pre-empted
                // TODO can maybe refactor and safely remove

                // TODO do a lil work-stealing
                interrupts::enable();
            }

            // Must have pending, but blocked, events
            if self.have_blocked_events() {
                self.awake_next_sleeper();
            }

            // Sleep until next interrupt
            interrupts::enable_and_hlt();
        }
    }

    /// Schedules an event with a specified priority level [0, NUM_EVENT_PRIORITIES)
    ///
    /// # Arguments
    /// * `future` - The future to wrap in an Event
    /// * `priority_level` - The priority level of the event to schedule
    /// * `pid` - The pid of the event to schedule
    pub fn schedule(
        &mut self,
        future: impl Future<Output = ()> + 'static + Send,
        priority_level: usize,
        pid: u32,
    ) -> Arc<Event> {
        if priority_level >= NUM_EVENT_PRIORITIES {
            panic!("Invalid event priority: {}", priority_level);
        } else {
            let event = Arc::new(Event::init(
                future,
                self.event_queues[priority_level].clone(),
                self.blocked_events.clone(),
                priority_level,
                pid,
                self.event_clock,
            ));

            Self::enqueue(&self.event_queues[priority_level], event.clone());

            self.pending_events.write().insert(event.eid.0);

            event.clone()
        }
    }

    /// Notifies runner of a blocked event
    /// Event MUST be awoken externally with .awake()
    ///
    /// # Arguments
    /// * `future` - The future to wrap in an Event
    /// * `priority_level` - The priority level of the event to schedule
    /// * `pid` - The pid of the event to schedule
    pub fn schedule_blocked(
        &mut self,
        future: impl Future<Output = ()> + 'static + Send,
        priority_level: usize,
        pid: u32,
    ) -> Arc<Event> {
        if priority_level >= NUM_EVENT_PRIORITIES {
            panic!("Invalid event priority: {}", priority_level);
        } else {
            let event = Arc::new(Event::init(
                future,
                self.event_queues[priority_level].clone(),
                self.blocked_events.clone(),
                priority_level,
                pid,
                self.event_clock,
            ));

            self.pending_events.write().insert(event.eid.0);
            self.blocked_events.write().insert(event.eid.0);

            event.clone()
        }
    }

    /// Returns a reference to the currently running event
    /// # Returns
    /// * `Option<&Arc<Event>>` - A reference to the currently running event, if it exists
    pub fn current_running_event(&self) -> Option<&Arc<Event>> {
        self.current_event.as_ref()
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
                    let output = future.await;
                    let output = if cancellation.is_cancelled() {
                        Err(TaskError::Cancelled)
                    } else {
                        Ok(output)
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
            let eid = without_interrupts(|| self.schedule(wrapped_future, priority_level, 0));

            JoinHandle {
                result,
                waker,
                eid: eid.eid,
                cancellation,
            }
        })
    }

    /// Increments the system timer (by one tick)
    pub fn inc_system_clock(&mut self) {
        self.system_clock += 1;
    }

    /// Increments the system timer (by one tick)
    pub fn get_system_time(&self) -> u64 {
        self.system_clock
    }

    /// Awakes the next sleeping event to be awoken, if it is time
    pub fn awake_next_sleeper(&mut self) {
        let sleeper = self.sleeping_events.peek();

        if sleeper.is_some() {
            let future = sleeper.unwrap();
            serial_println!("Awaken");
            if future.target_timestamp <= self.system_clock {
                future.awake();
                self.blocked_events.write().remove(&future.get_id());
                self.sleeping_events.pop();
            }
        }
    }

    /// Sets the current event to sleep for a given number of nanoseconds.
    ///
    /// # Arguments
    /// * `nanos` - The number of nanoseconds to sleep for
    ///
    /// # Returns
    /// * `Option<Sleep>` - A sleep future that can be awaited on (if there is an event to sleep)
    pub fn nanosleep_current_event(&mut self, nanos: u64) -> Option<Sleep> {
        self.current_event.as_ref().map(|e| {
            let system_ticks = nanos_to_ticks(nanos);

            let sleep = Sleep::new(self.system_clock + system_ticks, (*e).clone());
            self.sleeping_events.push(sleep.clone());
            self.blocked_events.write().insert(e.eid.0);

            sleep
        })
    }

    /// Creates a new event and immediately sets it to sleep
    ///
    /// # Arguments
    /// * `future` - The future to wrap in an Event
    /// * `priority_level` - The priority level of the event to schedule
    /// * `pid` - The pid of the event to schedule
    /// * `nanos` - The number of nanoseconds to sleep for
    pub fn nanosleep_event(
        &mut self,
        future: impl Future<Output = ()> + 'static + Send,
        priority_level: usize,
        pid: u32,
        nanos: u64,
    ) -> Option<Sleep> {
        if priority_level >= NUM_EVENT_PRIORITIES {
            panic!("Invalid event priority: {}", priority_level);
        } else {
            let event = Arc::new(Event::init(
                future,
                self.event_queues[priority_level].clone(),
                self.blocked_events.clone(),
                priority_level,
                pid,
                self.event_clock,
            ));

            let system_ticks = nanos_to_ticks(nanos);

            let sleep = Sleep::new(self.system_clock + system_ticks, event.clone());
            self.sleeping_events.push(sleep.clone());

            self.pending_events.write().insert(event.eid.0);
            self.blocked_events.write().insert(event.eid.0);

            Some(sleep)
        }
    }

    /// Blocks the current event until awoken
    ///
    /// # Returns
    /// * `Option<Block>` - A Block future that can be awaited on (if there is an event to block)
    #[allow(dead_code)]
    pub fn block_current_event(&mut self) -> Option<Sleep> {
        todo!();
    }

    /// # Returns
    /// * `bool` - true if there are blocked events on this runner
    fn have_blocked_events(&self) -> bool {
        !self.blocked_events.read().is_empty()
    }

    /// # Returns
    /// * `bool` - true if there are ready events on this runner
    fn have_unblocked_events(&self) -> bool {
        for queue in self.event_queues.iter() {
            if !queue.read().is_empty() {
                return true;
            }
        }

        false
    }

    /// # Arguments
    /// * `eid` - the eid of the event to check
    ///
    /// # Returns
    /// * `bool` - true if the event is pending on this runner
    fn contains_event(&self, eid: EventId) -> bool {
        self.pending_events.read().contains(&eid.0)
    }

    /// Retrieves the timestamp the next event in this queue was scheduled at
    ///
    /// # Arguments
    /// * `queue` - The queue to check
    ///
    /// # Returns
    /// * `Option<u64>` - The timestamp (in units of events run), if this queue has events
    fn next_event_timestamp(queue: &EventQueue) -> Option<u64> {
        queue
            .read()
            .front()
            .map(|e| e.scheduled_timestamp.load(Ordering::Relaxed))
    }

    /// Try to retrieve the next event from the queue
    ///
    /// # Arguments
    /// * `queue` - The queue to check
    ///
    /// # Returns
    /// * `Option<u64>` - The event to be run, if this queue has events
    fn try_pop(queue: &EventQueue) -> Option<Arc<Event>> {
        queue.write().pop_front()
    }

    /// Adds an event to the queue
    ///
    /// # Arguments
    /// * `queue` - The queue to check
    /// * `event` - The event to add
    fn enqueue(queue: &EventQueue, event: Arc<Event>) {
        queue.write().push_back(event);
    }

    /// Reprioritize events that have been waiting for a long time.
    fn reprioritize(&mut self) {
        for i in 1..NUM_EVENT_PRIORITIES {
            let scheduled_clock = Self::next_event_timestamp(&self.event_queues[i]);

            scheduled_clock.inspect(|event_scheduled_at| {
                if event_scheduled_at + PRIORITY_INC_DELAY <= self.event_clock {
                    let event_to_move = Self::try_pop(&self.event_queues[i]);
                    event_to_move.inspect(|e| {
                        Self::enqueue(&self.event_queues[i - 1], e.clone());

                        Self::change_priority(e, i - 1);
                        e.scheduled_timestamp
                            .swap(self.event_clock, Ordering::Relaxed);
                    });
                }
            });
        }
    }

    /// Changes the priority of a given event
    ///
    /// # Arguments
    /// * `event` - The event to modify
    /// * `priority` - The priority to change to
    fn change_priority(event: &Event, priority: usize) {
        event.priority.swap(priority, Ordering::Relaxed);
    }

    /// Finds the next event to be executed
    ///
    /// # Returns
    /// * `Option<Arc<Event>>` - The next event to be executed, if there is one
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
