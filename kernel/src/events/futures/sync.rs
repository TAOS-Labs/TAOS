use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    sync::atomic::{Ordering, AtomicBool}
};

use futures::task::ArcWake;

use crate::events::Event;

/// Future to block an event until a boolean is set to true (by some other event)
pub struct Condition {
    state: Arc<AtomicBool>,
    event: Arc<Event>,
}

unsafe impl Send for Condition {}

impl Condition {
    pub fn new(
        state: Arc<AtomicBool>,
        event: Arc<Event>,
    ) -> Condition {
        Condition {
            state,
            event,
        }
    }

    pub fn awake(&self) {
        self.event.clone().wake();
    }

    pub fn get_id(&self) -> u64 {
        self.event.eid.0
    }
}

impl Future for Condition {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
      if self.state.load(Ordering::Relaxed) {
          Poll::Ready(())
      } else {
          Poll::Pending
      }
  }
}
