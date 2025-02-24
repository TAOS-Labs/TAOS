use crate::serial_println;
use alloc::{
    boxed::Box,
    collections::{
        binary_heap::BinaryHeap, btree_map::BTreeMap, btree_set::BTreeSet, vec_deque::VecDeque,
    },
    sync::Arc,
};
use futures::Sleep;
use spin::{mutex::Mutex, rwlock::RwLock};
use x86_64::instructions::interrupts::without_interrupts;

use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use crate::{constants::events::NUM_EVENT_PRIORITIES, interrupts::x2apic, processes::process::run_process_ring3};

mod event;
mod event_runner;
mod futures;
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
    scheduled_timestamp: AtomicU64,
}

// Schedules and runs events within a single core
struct EventRunner {
    event_queues: [Arc<EventQueue>; NUM_EVENT_PRIORITIES],
    pending_events: RwLock<BTreeSet<u64>>,
    sleeping_events: BinaryHeap<Sleep>,
    current_event: Option<Arc<Event>>,
    event_clock: u64,
    system_clock: u64,
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
    future: impl Future<Output = ()> + 'static + Send,
    priority_level: usize,
) {
    let cpuid = x2apic::current_core_id() as u32;

    without_interrupts(|| {
        let runners = EVENT_RUNNERS.read();
        let mut runner = runners.get(&cpuid).expect("No runner found").write();

        runner.schedule(future, priority_level, 0);
    });
}

pub fn schedule_process(
    pid: u32, // 0 as kernel/sentinel
) {
    let cpuid = x2apic::current_core_id() as u32;

    without_interrupts(|| {
        let runners = EVENT_RUNNERS.read();
        let mut runner = runners.get(&cpuid).expect("No runner found").write();

        unsafe {
            runner.schedule(run_process_ring3(pid), NUM_EVENT_PRIORITIES - 1, pid);
        }
    });
}

pub fn schedule_blocked_process(
    pid: u32, // 0 as kernel/sentinel
) {
    let cpuid = x2apic::current_core_id() as u32;

    without_interrupts(|| {
        let runners = EVENT_RUNNERS.read();
        let mut runner = runners.get(&cpuid).expect("No runner found").write();

        unsafe {
            runner.schedule(run_process_ring3(pid), NUM_EVENT_PRIORITIES - 1, pid);
        }
    });

    todo!();
}

pub fn register_event_runner() {
    let cpuid = x2apic::current_core_id() as u32;

    without_interrupts(|| {
        let runner = EventRunner::init();
        let mut write_lock = EVENT_RUNNERS.write();

        write_lock.insert(cpuid, RwLock::new(runner));
    });
}

pub fn current_running_event_pid() -> u32 {
    let cpuid = x2apic::current_core_id() as u32;
    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").read();

    match runner.current_running_event() {
        Some(e) => e.pid,
        None => 0,
    }
}

pub fn current_running_event_priority() -> usize {
    let cpuid = x2apic::current_core_id() as u32;
    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").read();

    match runner.current_running_event() {
        Some(e) => e.priority.load(Ordering::Relaxed),
        None => NUM_EVENT_PRIORITIES - 1,
    }
}

pub fn inc_runner_clock() {
    let cpuid = x2apic::current_core_id() as u32;
    let runners = EVENT_RUNNERS.read();
    let mut runner = runners.get(&cpuid).expect("No runner found").write();

    runner.inc_system_clock();
}

pub fn runner_timestamp() -> u64 {
    let cpuid = x2apic::current_core_id() as u32;

    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").read();

    runner.system_clock
}

pub fn nanosleep_current_event(nanos: u64) -> Option<Sleep> {
    without_interrupts(|| {
        let cpuid = x2apic::current_core_id() as u32;

        let runners = EVENT_RUNNERS.read();
        let mut runner = runners.get(&cpuid).expect("No runner found").write();
    
        runner.nanosleep_current_event(nanos)
    })
}

pub fn nanosleep_current_process(
    pid: u32, // 0 as kernel/sentinel
    nanos: u64
) {
    let cpuid = x2apic::current_core_id() as u32;

    without_interrupts(|| {
        let runners = EVENT_RUNNERS.read();
        let mut runner = runners.get(&cpuid).expect("No runner found").write();

        unsafe {
            runner.nanosleep_event(run_process_ring3(pid), NUM_EVENT_PRIORITIES - 1, pid, nanos);
        }
    });
}

#[derive(Debug)]
pub struct EventInfo {
    pub priority: usize,
    pub pid: u32,
}

pub fn current_running_event_info() -> EventInfo {
    let cpuid = x2apic::current_core_id() as u32;

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
