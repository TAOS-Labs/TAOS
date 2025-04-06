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
pub struct Sleep {
    pub target_timestamp: u64,
    event: Arc<Event>,
}

impl Sleep {
    pub(in crate::events) fn new(target_timestamp: u64, event: Arc<Event>) -> Sleep {
        Sleep {
            target_timestamp,
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

/// Order sleep futures with earlier timestamps given "higher" values.
///
/// PID then EID to tie break.
/// Thus, events created earlier awaken first in the very rare event of a tie.
/// This helps preventing compounding error from old events frequently sleeping.
impl Ord for Sleep {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.target_timestamp
            .cmp(&other.target_timestamp)
            .reverse()
            .then(self.event.pid.cmp(&other.event.pid))
            .then(self.event.eid.cmp(&other.event.eid))
    }
}

impl PartialOrd for Sleep {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Sleep {
    fn eq(&self, other: &Self) -> bool {
        self.target_timestamp == other.target_timestamp
            && self.event.pid == other.event.pid
            && self.event.eid == other.event.eid
    }
}

impl Eq for Sleep {}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let system_time = runner_timestamp();

        if self.target_timestamp <= system_time {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
