use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};

use futures::task::ArcWake;

use crate::events::Event;

/// Future to block an event until a boolean is set to true (by some other event)
pub struct Condition {
    /// Ready or not
    state: Arc<AtomicBool>,
    /// The event to block on
    event: Arc<Event>,
}

unsafe impl Send for Condition {}

impl Condition {
    /// Create a new Condition
    ///
    /// * `state`: the starting state
    /// * `event`: the relevant event
    pub fn new(state: Arc<AtomicBool>, event: Arc<Event>) -> Condition {
        Condition { state, event }
    }

    /// The associated event is ready to make progress
    pub fn awake(&self) {
        self.event.clone().wake();
    }

    /// Returns the associated event id
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
