use super::{Event, EventId, EventQueue};
use alloc::{boxed::Box, collections::btree_set::BTreeSet, sync::Arc};
use core::{future::Future, sync::atomic::AtomicBool};
use futures::task::ArcWake;
use spin::{Mutex, RwLock};

impl Event {
    pub fn init(
        future: impl Future<Output = ()> + 'static + Send,
        rewake_queue: Arc<EventQueue>,
        blocked_events: Arc<RwLock<BTreeSet<u64>>>,
        priority: usize,
        pid: u32,
        scheduled_clock: u64,
    ) -> Event {
        Event {
            eid: EventId::init(),
            pid,
            future: Mutex::new(Box::pin(future)),
            rewake_queue,
            blocked_events,
            priority: priority.into(),
            scheduled_timestamp: scheduled_clock.into(),
            completed: AtomicBool::new(false),
        }
    }
}

impl ArcWake for Event {
    /// Push event back on the queue it is to awaken at
    /// And remove event from set of blocked events, if applicable
    ///
    /// Uses try_write() instead of write(): this is called from IRQ context
    /// (e.g. keyboard handler waking a reader), where blocking on a lock
    /// would deadlock with interrupts disabled. If the lock is contended,
    /// the wake is skipped — the next event will retry.
    fn wake_by_ref(arc: &Arc<Self>) {
        if let Some(mut queue) = arc.rewake_queue.try_write() {
            queue.push_back(arc.clone());
        }
        if let Some(mut blocked) = arc.blocked_events.try_write() {
            blocked.remove(&arc.eid.0);
        }
    }
}
