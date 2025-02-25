
use super::{Event, EventId, EventQueue};
use alloc::{boxed::Box, collections::btree_set::BTreeSet, sync::Arc};
use core::future::Future;
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
        }
    }
}

impl ArcWake for Event {
    fn wake_by_ref(arc: &Arc<Self>) {
        arc.rewake_queue.write().push_back(arc.clone());
        arc.blocked_events.write().remove(&arc.eid.0);
    }
}
