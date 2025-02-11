extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::Arc;

use core::future::Future;
use core::usize;

use spin::Mutex;

use futures::task::ArcWake;

use super::{Event, EventId, EventQueue};

impl Event {
    pub fn init(
        future: impl Future<Output = ()> + 'static + Send,
        rewake_queue: EventQueue,
        priority: usize,
    ) -> Event {
        Event {
            eid: EventId::init(),
            future: Mutex::new(Box::pin(future)),
            rewake_queue,
            priority,
        }
    }
}

impl ArcWake for Event {
    fn wake_by_ref(arc: &Arc<Self>) {
        let r: Result<(), Arc<Event>> = arc.rewake_queue.push(arc.clone());
        match r {
            Err(_) => {
                panic!("Event queue full!")
            }
            Ok(_) => {}
        }
    }
}
