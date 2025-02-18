use super::{Event, EventId, EventQueue};
use alloc::{boxed::Box, sync::Arc};
use core::future::Future;
use futures::task::ArcWake;
use spin::Mutex;

impl Event {
    pub fn init(
        future: impl Future<Output = ()> + 'static + Send,
        rewake_queue: EventQueue,
        priority: usize,
        pid: u32,
    ) -> Event {
        Event {
            eid: EventId::init(),
            pid,
            future: Mutex::new(Box::pin(future)),
            rewake_queue,
            priority,
        }
    }
}

impl ArcWake for Event {
    fn wake_by_ref(arc: &Arc<Self>) {
        arc.rewake_queue.push(arc.clone());
    }
}
