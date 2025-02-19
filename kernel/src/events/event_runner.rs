use super::{Event, EventRunner};

use alloc::{collections::btree_set::BTreeSet, sync::Arc};
use futures::task::waker_ref;
use spin::rwlock::RwLock;
use x86_64::instructions::interrupts;

use core::{
    future::Future,
    task::{Context, Poll},
};

use crossbeam_queue::SegQueue;

use crate::constants::events::NUM_EVENT_PRIORITIES;

impl EventRunner {
    pub fn init() -> EventRunner {
        EventRunner {
            event_queues: core::array::from_fn(|_| Arc::new(SegQueue::new())),
            rewake_queue: Arc::new(SegQueue::new()),
            pending_events: RwLock::new(BTreeSet::new()),
            current_event: None,
        }
    }

    fn next_event(&mut self) -> Option<Arc<Event>> {
        if !self.rewake_queue.is_empty() {
            self.rewake_queue.pop()
        } else {
            let mut event = None;
            for i in 0..NUM_EVENT_PRIORITIES {
                if !self.event_queues[i].is_empty() {
                    event = self.event_queues[i].pop();
                    break;
                }
            }

            event
        }
    }

    pub fn run_loop(&mut self) -> ! {
        loop {
            loop {
                {
                    let read_lock = self.pending_events.read();

                    if read_lock.is_empty() {
                        break;
                    }
                }

                self.current_event = self.next_event();

                let event = self
                    .current_event
                    .as_ref()
                    .expect("Have pending events, but empty waiting queues.");

                let pe_read_lock = self.pending_events.read();
                if pe_read_lock.contains(&event.eid.0) {
                    drop(pe_read_lock);
                    let waker = waker_ref(event);
                    let mut context: Context<'_> = Context::from_waker(&waker);

                    let mut future_guard = event.future.lock();

                    let ready: bool = future_guard.as_mut().poll(&mut context) != Poll::Pending;

                    drop(future_guard);

                    if !ready {
                        self.event_queues[event.priority].push(event.clone());
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
            let arc = Arc::new(Event::init(
                future,
                self.rewake_queue.clone(),
                priority_level,
                pid,
            ));

            self.event_queues[priority_level].push(arc.clone());
            let mut write_lock = self.pending_events.write();
            write_lock.insert(arc.eid.0);
        }
    }

    pub fn current_running_event(&self) -> Option<&Arc<Event>> {
        self.current_event.as_ref()
    }
}
