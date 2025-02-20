use super::{Event, EventId, EventQueue};
use alloc::{boxed::Box, sync::Arc};
use core::future::Future;
use futures::task::ArcWake;
use spin::Mutex;

impl Event {
    pub fn init(
        future: impl Future<Output = ()> + 'static + Send,
        rewake_queue: Arc<EventQueue>,
        priority: usize,
        pid: u32,
    ) -> Event {
        Event {
            eid: EventId::init(),
            pid: pid,
            future: Mutex::new(Box::pin(future)),
            rewake_queue: rewake_queue,
            priority: priority,
        }
    }
}

impl ArcWake for Event {
    fn wake_by_ref(arc: &Arc<Self>) {
        let mut wlock = arc.rewake_queue.write();
        wlock.push_back(arc.clone());
    }
}
