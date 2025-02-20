use alloc::{
    boxed::Box,
    collections::{btree_map::BTreeMap, btree_set::BTreeSet, vec_deque::VecDeque},
    sync::Arc,
};
use spin::{mutex::Mutex, rwlock::RwLock};
use x86_64::instructions::interrupts::without_interrupts;

use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use crate::constants::events::NUM_EVENT_PRIORITIES;

mod event;
mod event_runner;
mod tasks;

pub use tasks::{
    yield_task::{yield_now, Yield},
    JoinHandle,
};

// Thread-safe future that remains pinned to a heap address throughout its lifetime
type SendFuture = Mutex<Pin<Box<dyn Future<Output = ()> + 'static + Send>>>;

// Thread-safe static queue of events
type EventQueue = RwLock<VecDeque<Arc<Event>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EventId(u64);

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
    pid: u32,
    future: SendFuture,
    rewake_queue: Arc<EventQueue>,
    priority: AtomicUsize,
    scheduled_clock: AtomicU64,
}

// Schedules and runs events within a single core
struct EventRunner {
    event_queues: [EventQueue; NUM_EVENT_PRIORITIES],
    rewake_queue: Arc<EventQueue>,
    pending_events: RwLock<BTreeSet<u64>>,
    current_event: Option<Arc<Event>>,
    clock: u64,
}

// Global mapping of cores to events
// TODO will need to expand when distributed, like most globals
static EVENT_RUNNERS: RwLock<BTreeMap<u32, RwLock<EventRunner>>> = RwLock::new(BTreeMap::new());

/// # Safety
///
/// TODO
pub unsafe fn run_loop(cpuid: u32) -> ! {
    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").as_mut_ptr();

    (*runner).run_loop()
}

pub fn schedule_kernel(
    cpuid: u32,
    future: impl Future<Output = ()> + 'static + Send,
    priority_level: usize,
) {
    let runners = EVENT_RUNNERS.read();
    let mut runner = runners.get(&cpuid).expect("No runner found").write();

    runner.schedule(future, priority_level, 0);
}

pub fn schedule_process(
    cpuid: u32,
    future: impl Future<Output = ()> + 'static + Send,
    pid: u32, // 0 as kernel/sentinel
) {
    without_interrupts(|| {
        let runners = EVENT_RUNNERS.read();
        let mut runner = runners.get(&cpuid).expect("No runner found").write();

        runner.schedule(future, NUM_EVENT_PRIORITIES - 1, pid);
    });
}

pub fn register_event_runner(cpuid: u32) {
    without_interrupts(|| {
        let runner = EventRunner::init();
        let mut write_lock = EVENT_RUNNERS.write();

        write_lock.insert(cpuid, RwLock::new(runner));
    });
}

pub fn current_running_event_pid(cpuid: u32) -> u32 {
    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").write();

    match runner.current_running_event() {
        Some(e) => e.pid,
        None => 0,
    }
}

pub fn current_running_event_priority(cpuid: u32) -> usize {
    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").write();

    match runner.current_running_event() {
        Some(e) => e.priority.load(Ordering::Relaxed),
        None => NUM_EVENT_PRIORITIES - 1,
    }
}

#[derive(Debug)]
pub struct EventInfo {
    pub priority: usize,
    pub pid: u32,
}

// im gonna double check the place where i called create process, it might just be cpu id

// most likely it isn't finding any event
pub fn current_running_event_info(cpuid: u32) -> EventInfo {
    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").write();

    match runner.current_running_event() {
        Some(e) => EventInfo {
            priority: e.priority.load(Ordering::Relaxed),
            pid: e.pid,
        },
        None => EventInfo {
            priority: NUM_EVENT_PRIORITIES - 1,
            pid: 0,
        },
    }
}

pub fn spawn<F, T>(cpuid: u32, future: F, priority_level: usize) -> JoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let runners = EVENT_RUNNERS.read();
    let mut runner = runners.get(&cpuid).expect("No runner found").write();

    runner.spawn(future, priority_level)
}
