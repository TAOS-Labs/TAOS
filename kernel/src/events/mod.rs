extern crate alloc;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use alloc::{boxed::Box, collections::btree_set::BTreeSet};
use spin::mutex::Mutex;
use spin::rwlock::RwLock;

use core::{future::Future, pin::Pin, sync::atomic::AtomicU64, sync::atomic::Ordering};

use crossbeam_queue::ArrayQueue;

use crate::constants::events::NUM_EVENT_PRIORITIES;

mod event;
mod event_runner;
pub mod futures;

// Thread-safe future that remains pinned to a heap address throughout its lifetime
type SendFuture = Mutex<Pin<Box<dyn Future<Output = ()> + 'static + Send>>>;

// Thread-safe static queue of events
type EventQueue = Arc<ArrayQueue<Arc<Event>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct EventId(u64);

// Unique global ID for events.
// TODO this, like most globals, will likely need to change when distributed
impl EventId {
    fn init() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        EventId(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

// Describes a future and its scheduling context
struct Event {
    eid: EventId,
    future: SendFuture,
    rewake_queue: EventQueue,
    priority: usize,
}

// Schedules and runs events within a single core
#[derive(Debug)]
struct EventRunner {
    event_queues: [EventQueue; NUM_EVENT_PRIORITIES],
    rewake_queue: EventQueue,
    pending_events: RwLock<BTreeSet<u64>>,
}

// Global mapping of cores to events
// TODO will need to expand when distributed, like most globals
static EVENT_RUNNERS: RwLock<BTreeMap<u32, RwLock<EventRunner>>> = RwLock::new(BTreeMap::new());

pub unsafe fn run_loop(cpuid: u32) -> ! {
    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").as_mut_ptr();

    (*runner).run_loop()
}

pub fn schedule(
    cpuid: u32,
    future: impl Future<Output = ()> + 'static + Send,
    priority_level: usize,
) {
    let runners = EVENT_RUNNERS.read();
    let mut runner = runners.get(&cpuid).expect("No runner found").write();

    runner.schedule(future, priority_level);
}

pub fn register_event_runner(cpuid: u32) {
    let runner = EventRunner::init();
    let mut write_lock = EVENT_RUNNERS.write();

    write_lock.insert(cpuid, RwLock::new(runner));
}
