use alloc::{
    boxed::Box,
    collections::{
        binary_heap::BinaryHeap, btree_map::BTreeMap, btree_set::BTreeSet, vec_deque::VecDeque,
    },
    sync::Arc,
};
use futures::sleep::Sleep;
use spin::{mutex::Mutex, rwlock::RwLock};
use x86_64::instructions::interrupts::without_interrupts;

use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

use crate::{
    constants::events::NUM_EVENT_PRIORITIES, interrupts::x2apic::{self, nanos_to_ticks},
    processes::process::run_process_ring3,
};

mod event;
mod event_runner;

pub mod futures;

/// Thread-safe future that remains pinned to a heap address throughout its lifetime
type SendFuture = Mutex<Pin<Box<dyn Future<Output = ()> + 'static + Send>>>;

/// Thread-safe static queue of events
type EventQueue = RwLock<VecDeque<Arc<Event>>>;

/// Unique global ID for events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct EventId(u64);

impl EventId {
    fn init() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        EventId(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

/// Describes a future and its scheduling context
pub struct Event {
    eid: EventId,
    pid: u32,
    future: SendFuture,
    rewake_queue: Arc<EventQueue>,
    blocked_events: Arc<RwLock<BTreeSet<u64>>>,
    priority: AtomicUsize,
    scheduled_timestamp: AtomicU64,
    completed: AtomicBool
}

/// Schedules and runs events within a single core
struct EventRunner {
    event_queues: [Arc<EventQueue>; NUM_EVENT_PRIORITIES],
    pending_events: RwLock<BTreeSet<u64>>,
    blocked_events: Arc<RwLock<BTreeSet<u64>>>,
    sleeping_events: BinaryHeap<Sleep>,
    current_event: Option<Arc<Event>>,
    event_clock: u64,
    system_clock: u64,
}

/// Global mapping of cores to events
static EVENT_RUNNERS: RwLock<BTreeMap<u32, RwLock<EventRunner>>> = RwLock::new(BTreeMap::new());

/// Continuously schedules and runs events in loop
///
/// # Safety
/// This function should only be run once per core.
/// Invoking this function should be the final step of the boot process.
pub unsafe fn run_loop(cpuid: u32) -> ! {
    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").as_mut_ptr();

    (*runner).run_loop()
}

/// Schedules a kernel event
///
/// PID will always be 0
pub fn schedule_kernel(future: impl Future<Output = ()> + 'static + Send, priority_level: usize) -> Arc<Event> {
    let cpuid = x2apic::current_core_id() as u32;

    without_interrupts(|| {
        let runners = EVENT_RUNNERS.read();
        let mut runner = runners.get(&cpuid).expect("No runner found").write();

        runner.schedule(future, priority_level, 0)
    })
}

/// Schedules a user process
/// Starts with minimum priority
pub fn schedule_process(pid: u32, // 0 as kernel/sentinel
) -> Arc<Event> {
    let cpuid = x2apic::current_core_id() as u32;

    without_interrupts(|| {
        let runners = EVENT_RUNNERS.read();
        let mut runner = runners.get(&cpuid).expect("No runner found").write();

        unsafe {
            runner.schedule(run_process_ring3(pid), NUM_EVENT_PRIORITIES - 1, pid)
        }
    })
}

/// Notifies runner of a user process,
/// but does not immediately schedule for polling.
/// Starts with minimum priority
pub fn schedule_blocked_process(pid: u32, // 0 as kernel/sentinel
)  -> Arc<Event> {
    let cpuid = x2apic::current_core_id() as u32;

    without_interrupts(|| {
        let runners = EVENT_RUNNERS.read();
        let mut runner = runners.get(&cpuid).expect("No runner found").write();

        unsafe {
            runner.schedule_blocked(run_process_ring3(pid), NUM_EVENT_PRIORITIES - 1, pid)
        }
    })

    //todo?
}

/// Registers a new event runner to the current core
pub fn register_event_runner() {
    let cpuid = x2apic::current_core_id() as u32;

    without_interrupts(|| {
        let runner = EventRunner::init();
        let mut write_lock = EVENT_RUNNERS.write();

        write_lock.insert(cpuid, RwLock::new(runner));
    });
}

pub fn current_running_event() -> Option<Arc<Event>> {
    let cpuid = x2apic::current_core_id() as u32;
    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").read();

    runner.current_running_event().cloned()
}

/// Finds the PID of the current event running on this core
///
/// # Returns
/// * `u32` - The PID of the event (0 for kernel tasks)
pub fn current_running_event_pid() -> u32 {
    let cpuid = x2apic::current_core_id() as u32;
    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").read();

    match runner.current_running_event() {
        Some(e) => e.pid,
        None => 0,
    }
}

/// Finds the priority of the current event running on this core
///
/// # Returns
/// * `usize` - The priority of the event (0 for max priority)
pub fn current_running_event_priority() -> usize {
    let cpuid = x2apic::current_core_id() as u32;
    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").read();

    match runner.current_running_event() {
        Some(e) => e.priority.load(Ordering::Relaxed),
        None => NUM_EVENT_PRIORITIES - 1,
    }
}

/// Increments the system time by one tick
pub fn inc_runner_clock() {
    let cpuid = x2apic::current_core_id() as u32;
    let runners = EVENT_RUNNERS.read();
    let mut runner = runners.get(&cpuid).expect("No runner found").write();

    runner.inc_system_clock();
}

pub fn get_runner_time(offset_nanos: u64) -> u64 {
    let cpuid = x2apic::current_core_id() as u32;
    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").read();

    runner.get_system_time() + nanos_to_ticks(offset_nanos)
}

/// Gets the current system time (in ticks)
///
/// # Returns
/// * `u64` - the current system time (in ticks)
pub fn runner_timestamp() -> u64 {
    let cpuid = x2apic::current_core_id() as u32;

    let runners = EVENT_RUNNERS.read();
    let runner = runners.get(&cpuid).expect("No runner found").read();

    runner.system_clock
}

/// Sets the current event to sleep for a given number of nanoseconds.
/// Use to sleep kernel events.
///
/// # Arguments
/// * `nanos` - The number of nanoseconds to sleep for
///
/// # Returns
/// * `Option<Sleep>` - A sleep future that can be awaited on (if there is an event to sleep)
pub fn nanosleep_current_event(nanos: u64) -> Option<Sleep> {
    without_interrupts(|| {
        let cpuid = x2apic::current_core_id() as u32;

        let runners = EVENT_RUNNERS.read();
        let mut runner = runners.get(&cpuid).expect("No runner found").write();

        runner.nanosleep_current_event(nanos)
    })
}

/// Sets the current process to sleep for a given number of nanoseconds.
///
/// # Arguments
/// * `pid` - The pid of the process to sleep
/// * `nanos` - The number of nanoseconds to sleep for
pub fn nanosleep_current_process(
    pid: u32, // 0 as kernel/sentinel
    nanos: u64,
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

/// Event info publicly available outside events module
#[derive(Debug)]
pub struct EventInfo {
    pub priority: usize,
    pub pid: u32,
}

/// Retrieves information about the currently running event
///
/// # Returns
/// * `EventInfo` - The priority and pid of the current running event
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
