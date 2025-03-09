use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::task::ArcWake;

use crate::{
    devices::sd_card::{PresentState, SDCardError},
    events::{runner_timestamp, Event},
};

/// Future to sleep an event until a target timestamp (in system ticks)
#[derive(Clone)]
pub struct SDCardReq {
    target_state: PresentState,
    present_state_register_addr: *const u32,
    timeout_timestamp: u64,
    event: Arc<Event>,
}

unsafe impl Send for SDCardReq {}

impl SDCardReq {
    pub fn new(
        target_state: PresentState,
        present_state_register_addr: *const u32,
        timeout_timestamp: u64,
        event: Arc<Event>,
    ) -> SDCardReq {
        SDCardReq {
            present_state_register_addr,
            target_state,
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
impl Ord for SDCardReq {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.timeout_timestamp
            .cmp(&other.timeout_timestamp)
            .reverse()
            .then(self.event.pid.cmp(&other.event.pid))
            .then(self.event.eid.cmp(&other.event.eid))
    }
}

impl PartialOrd for SDCardReq {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SDCardReq {
    fn eq(&self, other: &Self) -> bool {
        self.timeout_timestamp == other.timeout_timestamp
            && self.event.pid == other.event.pid
            && self.event.eid == other.event.eid
    }
}

impl Eq for SDCardReq {}

impl Future for SDCardReq {
    type Output = Result<(), SDCardError>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let system_time = runner_timestamp();

        if self.timeout_timestamp <= system_time {
            return Poll::Ready(Result::Err(SDCardError::SDTimeout));
        }

        let present_state = unsafe {
            PresentState::from_bits_retain(core::ptr::read_volatile(
                self.present_state_register_addr,
            ))
        };

        if self.target_state.intersects(present_state) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
