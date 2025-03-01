use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::task::ArcWake;

use crate::events::{runner_timestamp, Event};

/// Future to sleep an event until a target timestamp (in system ticks)
#[derive(Clone)]
pub struct Await {
    target_event: Arc<Event>,
    timeout_timestamp: u64,
    event: Arc<Event>,
}

unsafe impl Send for Await {
}

impl Await {
    pub fn new(
      target_event: Arc<Event>, 
      timeout_timestamp: u64, 
      event: Arc<Event>) -> Await {
        Await {
          target_event,
          timeout_timestamp,
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

/// Order SDCardReq futures with earlier timestamps given "higher" values.
///
/// PID then EID to tie break.
/// Thus, events created earlier awaken first in the very rare event of a tie.
/// This helps preventing compounding error from old events frequently blocking.
impl Ord for Await {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.timeout_timestamp
            .cmp(&other.timeout_timestamp)
            .reverse()
            .then(self.target_event.pid.cmp(&other.target_event.pid))
            .then(self.target_event.eid.cmp(&other.target_event.eid))
            .then(self.event.pid.cmp(&other.event.pid))
            .then(self.event.eid.cmp(&other.event.eid))
    }
}

impl PartialOrd for Await {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Await {
    fn eq(&self, other: &Self) -> bool {
        self.timeout_timestamp == other.timeout_timestamp
            && self.target_event.pid == other.target_event.pid
            && self.target_event.eid == other.target_event.eid
            && self.event.pid == other.event.pid
            && self.event.eid == other.event.eid
    }
}

impl Eq for Await {}

impl Future for Await {
    type Output = Result<(), ()>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let system_time = runner_timestamp();

        if self.target_event.completed.load(core::sync::atomic::Ordering::Relaxed) {
          Poll::Ready(Result::Ok(()))
        } else if self.timeout_timestamp <= system_time {
          Poll::Ready(Result::Err(()))
        } else {
          Poll::Pending
        }
    }
}
